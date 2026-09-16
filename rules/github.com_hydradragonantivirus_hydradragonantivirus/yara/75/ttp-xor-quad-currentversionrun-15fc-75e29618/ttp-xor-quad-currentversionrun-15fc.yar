rule TTP_XOR_QUAD_CurrentVersionRun_15fc {
  strings:
    $key_15fc = { 46 93 [2] 62 9d [2] 49 b1 [2] 67 93 [2] 73 88 [2] 7c 92 [2] 62 8f [2] 60 8e [2] 7b 88 [2] 67 8f [2] 7b a0 }

  condition:
    any of them
}