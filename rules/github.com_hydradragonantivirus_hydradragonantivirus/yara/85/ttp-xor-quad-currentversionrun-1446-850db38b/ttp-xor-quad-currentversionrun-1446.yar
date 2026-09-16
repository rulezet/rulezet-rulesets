rule TTP_XOR_QUAD_CurrentVersionRun_1446 {
  strings:
    $key_1446 = { 47 29 [2] 63 27 [2] 48 0b [2] 66 29 [2] 72 32 [2] 7d 28 [2] 63 35 [2] 61 34 [2] 7a 32 [2] 66 35 [2] 7a 1a }

  condition:
    any of them
}