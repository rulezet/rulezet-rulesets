rule TTP_XOR_QUAD_CurrentVersionRun_1646 {
  strings:
    $key_1646 = { 45 29 [2] 61 27 [2] 4a 0b [2] 64 29 [2] 70 32 [2] 7f 28 [2] 61 35 [2] 63 34 [2] 78 32 [2] 64 35 [2] 78 1a }

  condition:
    any of them
}