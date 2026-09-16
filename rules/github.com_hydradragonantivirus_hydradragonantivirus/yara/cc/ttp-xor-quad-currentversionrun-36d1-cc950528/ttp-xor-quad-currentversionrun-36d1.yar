rule TTP_XOR_QUAD_CurrentVersionRun_36d1 {
  strings:
    $key_36d1 = { 65 be [2] 41 b0 [2] 6a 9c [2] 44 be [2] 50 a5 [2] 5f bf [2] 41 a2 [2] 43 a3 [2] 58 a5 [2] 44 a2 [2] 58 8d }

  condition:
    any of them
}