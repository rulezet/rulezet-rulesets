rule TTP_XOR_QUAD_CurrentVersionRun_5d0a {
  strings:
    $key_5d0a = { 0e 65 [2] 2a 6b [2] 01 47 [2] 2f 65 [2] 3b 7e [2] 34 64 [2] 2a 79 [2] 28 78 [2] 33 7e [2] 2f 79 [2] 33 56 }

  condition:
    any of them
}