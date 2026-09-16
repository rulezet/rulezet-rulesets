rule TTP_XOR_QUAD_CurrentVersionRun_5dcc {
  strings:
    $key_5dcc = { 0e a3 [2] 2a ad [2] 01 81 [2] 2f a3 [2] 3b b8 [2] 34 a2 [2] 2a bf [2] 28 be [2] 33 b8 [2] 2f bf [2] 33 90 }

  condition:
    any of them
}