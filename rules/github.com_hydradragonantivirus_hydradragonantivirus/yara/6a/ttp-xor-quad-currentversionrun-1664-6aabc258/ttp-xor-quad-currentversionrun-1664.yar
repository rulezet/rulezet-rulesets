rule TTP_XOR_QUAD_CurrentVersionRun_1664 {
  strings:
    $key_1664 = { 45 0b [2] 61 05 [2] 4a 29 [2] 64 0b [2] 70 10 [2] 7f 0a [2] 61 17 [2] 63 16 [2] 78 10 [2] 64 17 [2] 78 38 }

  condition:
    any of them
}