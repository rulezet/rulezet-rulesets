rule TTP_XOR_QUAD_CurrentVersionRun_1405 {
  strings:
    $key_1405 = { 47 6a [2] 63 64 [2] 48 48 [2] 66 6a [2] 72 71 [2] 7d 6b [2] 63 76 [2] 61 77 [2] 7a 71 [2] 66 76 [2] 7a 59 }

  condition:
    any of them
}