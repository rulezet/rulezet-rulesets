rule TTP_XOR_QUAD_CurrentVersionRun_1658 {
  strings:
    $key_1658 = { 45 37 [2] 61 39 [2] 4a 15 [2] 64 37 [2] 70 2c [2] 7f 36 [2] 61 2b [2] 63 2a [2] 78 2c [2] 64 2b [2] 78 04 }

  condition:
    any of them
}