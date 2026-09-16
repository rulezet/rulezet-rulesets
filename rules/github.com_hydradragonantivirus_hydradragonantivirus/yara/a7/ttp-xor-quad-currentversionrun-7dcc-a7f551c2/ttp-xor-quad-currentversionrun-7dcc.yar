rule TTP_XOR_QUAD_CurrentVersionRun_7dcc {
  strings:
    $key_7dcc = { 2e a3 [2] 0a ad [2] 21 81 [2] 0f a3 [2] 1b b8 [2] 14 a2 [2] 0a bf [2] 08 be [2] 13 b8 [2] 0f bf [2] 13 90 }

  condition:
    any of them
}