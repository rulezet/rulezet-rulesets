rule TTP_XOR_QUAD_CurrentVersionRun_fdcc {
  strings:
    $key_fdcc = { ae a3 [2] 8a ad [2] a1 81 [2] 8f a3 [2] 9b b8 [2] 94 a2 [2] 8a bf [2] 88 be [2] 93 b8 [2] 8f bf [2] 93 90 }

  condition:
    any of them
}