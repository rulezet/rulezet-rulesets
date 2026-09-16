rule TTP_XOR_QUAD_CurrentVersionRun_1644 {
  strings:
    $key_1644 = { 45 2b [2] 61 25 [2] 4a 09 [2] 64 2b [2] 70 30 [2] 7f 2a [2] 61 37 [2] 63 36 [2] 78 30 [2] 64 37 [2] 78 18 }

  condition:
    any of them
}