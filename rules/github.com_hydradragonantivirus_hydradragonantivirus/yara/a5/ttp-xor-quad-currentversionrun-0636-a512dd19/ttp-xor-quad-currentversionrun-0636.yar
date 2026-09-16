rule TTP_XOR_QUAD_CurrentVersionRun_0636 {
  strings:
    $key_0636 = { 55 59 [2] 71 57 [2] 5a 7b [2] 74 59 [2] 60 42 [2] 6f 58 [2] 71 45 [2] 73 44 [2] 68 42 [2] 74 45 [2] 68 6a }

  condition:
    any of them
}