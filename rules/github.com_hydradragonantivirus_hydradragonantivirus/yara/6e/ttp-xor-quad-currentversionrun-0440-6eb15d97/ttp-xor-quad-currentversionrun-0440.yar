rule TTP_XOR_QUAD_CurrentVersionRun_0440 {
  strings:
    $key_0440 = { 57 2f [2] 73 21 [2] 58 0d [2] 76 2f [2] 62 34 [2] 6d 2e [2] 73 33 [2] 71 32 [2] 6a 34 [2] 76 33 [2] 6a 1c }

  condition:
    any of them
}