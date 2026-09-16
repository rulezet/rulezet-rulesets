rule TTP_XOR_QUAD_CurrentVersionRun_77d1 {
  strings:
    $key_77d1 = { 24 be [2] 00 b0 [2] 2b 9c [2] 05 be [2] 11 a5 [2] 1e bf [2] 00 a2 [2] 02 a3 [2] 19 a5 [2] 05 a2 [2] 19 8d }

  condition:
    any of them
}