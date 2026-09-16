rule TTP_XOR_QUAD_CurrentVersionRun_043b {
  strings:
    $key_043b = { 57 54 [2] 73 5a [2] 58 76 [2] 76 54 [2] 62 4f [2] 6d 55 [2] 73 48 [2] 71 49 [2] 6a 4f [2] 76 48 [2] 6a 67 }

  condition:
    any of them
}