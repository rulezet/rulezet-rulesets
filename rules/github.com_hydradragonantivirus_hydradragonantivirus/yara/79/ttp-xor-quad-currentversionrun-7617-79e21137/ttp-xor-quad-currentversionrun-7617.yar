rule TTP_XOR_QUAD_CurrentVersionRun_7617 {
  strings:
    $key_7617 = { 25 78 [2] 01 76 [2] 2a 5a [2] 04 78 [2] 10 63 [2] 1f 79 [2] 01 64 [2] 03 65 [2] 18 63 [2] 04 64 [2] 18 4b }

  condition:
    any of them
}