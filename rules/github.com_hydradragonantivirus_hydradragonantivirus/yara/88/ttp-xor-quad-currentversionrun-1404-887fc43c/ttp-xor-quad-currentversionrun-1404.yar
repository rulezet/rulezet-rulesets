rule TTP_XOR_QUAD_CurrentVersionRun_1404 {
  strings:
    $key_1404 = { 47 6b [2] 63 65 [2] 48 49 [2] 66 6b [2] 72 70 [2] 7d 6a [2] 63 77 [2] 61 76 [2] 7a 70 [2] 66 77 [2] 7a 58 }

  condition:
    any of them
}