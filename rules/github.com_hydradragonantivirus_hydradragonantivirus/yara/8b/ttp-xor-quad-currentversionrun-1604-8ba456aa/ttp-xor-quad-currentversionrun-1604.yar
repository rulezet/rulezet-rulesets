rule TTP_XOR_QUAD_CurrentVersionRun_1604 {
  strings:
    $key_1604 = { 45 6b [2] 61 65 [2] 4a 49 [2] 64 6b [2] 70 70 [2] 7f 6a [2] 61 77 [2] 63 76 [2] 78 70 [2] 64 77 [2] 78 58 }

  condition:
    any of them
}