rule TTP_XOR_QUAD_CurrentVersionRun_56fc {
  strings:
    $key_56fc = { 05 93 [2] 21 9d [2] 0a b1 [2] 24 93 [2] 30 88 [2] 3f 92 [2] 21 8f [2] 23 8e [2] 38 88 [2] 24 8f [2] 38 a0 }

  condition:
    any of them
}