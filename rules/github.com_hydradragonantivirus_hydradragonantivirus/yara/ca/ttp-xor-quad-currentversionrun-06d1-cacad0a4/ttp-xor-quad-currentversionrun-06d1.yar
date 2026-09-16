rule TTP_XOR_QUAD_CurrentVersionRun_06d1 {
  strings:
    $key_06d1 = { 55 be [2] 71 b0 [2] 5a 9c [2] 74 be [2] 60 a5 [2] 6f bf [2] 71 a2 [2] 73 a3 [2] 68 a5 [2] 74 a2 [2] 68 8d }

  condition:
    any of them
}