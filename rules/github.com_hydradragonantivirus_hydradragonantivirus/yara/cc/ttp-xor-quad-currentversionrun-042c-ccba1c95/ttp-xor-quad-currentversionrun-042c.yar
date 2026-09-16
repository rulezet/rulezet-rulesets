rule TTP_XOR_QUAD_CurrentVersionRun_042c {
  strings:
    $key_042c = { 57 43 [2] 73 4d [2] 58 61 [2] 76 43 [2] 62 58 [2] 6d 42 [2] 73 5f [2] 71 5e [2] 6a 58 [2] 76 5f [2] 6a 70 }

  condition:
    any of them
}