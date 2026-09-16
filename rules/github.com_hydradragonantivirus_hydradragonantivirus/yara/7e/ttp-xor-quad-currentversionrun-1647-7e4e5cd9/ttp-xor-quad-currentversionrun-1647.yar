rule TTP_XOR_QUAD_CurrentVersionRun_1647 {
  strings:
    $key_1647 = { 45 28 [2] 61 26 [2] 4a 0a [2] 64 28 [2] 70 33 [2] 7f 29 [2] 61 34 [2] 63 35 [2] 78 33 [2] 64 34 [2] 78 1b }

  condition:
    any of them
}