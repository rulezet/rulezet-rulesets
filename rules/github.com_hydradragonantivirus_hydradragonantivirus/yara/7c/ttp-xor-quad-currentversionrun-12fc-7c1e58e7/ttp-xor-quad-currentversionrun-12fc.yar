rule TTP_XOR_QUAD_CurrentVersionRun_12fc {
  strings:
    $key_12fc = { 41 93 [2] 65 9d [2] 4e b1 [2] 60 93 [2] 74 88 [2] 7b 92 [2] 65 8f [2] 67 8e [2] 7c 88 [2] 60 8f [2] 7c a0 }

  condition:
    any of them
}