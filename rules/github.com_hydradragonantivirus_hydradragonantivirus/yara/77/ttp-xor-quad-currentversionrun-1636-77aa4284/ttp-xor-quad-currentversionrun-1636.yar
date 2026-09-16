rule TTP_XOR_QUAD_CurrentVersionRun_1636 {
  strings:
    $key_1636 = { 45 59 [2] 61 57 [2] 4a 7b [2] 64 59 [2] 70 42 [2] 7f 58 [2] 61 45 [2] 63 44 [2] 78 42 [2] 64 45 [2] 78 6a }

  condition:
    any of them
}