rule TTP_XOR_QUAD_CurrentVersionRun_5f36 {
  strings:
    $key_5f36 = { 0c 59 [2] 28 57 [2] 03 7b [2] 2d 59 [2] 39 42 [2] 36 58 [2] 28 45 [2] 2a 44 [2] 31 42 [2] 2d 45 [2] 31 6a }

  condition:
    any of them
}