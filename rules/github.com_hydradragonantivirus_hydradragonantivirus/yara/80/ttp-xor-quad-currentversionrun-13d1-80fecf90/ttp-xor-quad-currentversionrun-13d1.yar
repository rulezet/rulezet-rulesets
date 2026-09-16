rule TTP_XOR_QUAD_CurrentVersionRun_13d1 {
  strings:
    $key_13d1 = { 40 be [2] 64 b0 [2] 4f 9c [2] 61 be [2] 75 a5 [2] 7a bf [2] 64 a2 [2] 66 a3 [2] 7d a5 [2] 61 a2 [2] 7d 8d }

  condition:
    any of them
}