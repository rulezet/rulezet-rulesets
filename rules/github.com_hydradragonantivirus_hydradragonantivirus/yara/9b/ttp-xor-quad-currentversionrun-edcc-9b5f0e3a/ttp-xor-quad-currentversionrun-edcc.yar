rule TTP_XOR_QUAD_CurrentVersionRun_edcc {
  strings:
    $key_edcc = { be a3 [2] 9a ad [2] b1 81 [2] 9f a3 [2] 8b b8 [2] 84 a2 [2] 9a bf [2] 98 be [2] 83 b8 [2] 9f bf [2] 83 90 }

  condition:
    any of them
}