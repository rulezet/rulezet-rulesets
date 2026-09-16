rule TTP_XOR_QUAD_CurrentVersionRun_fccc {
  strings:
    $key_fccc = { af a3 [2] 8b ad [2] a0 81 [2] 8e a3 [2] 9a b8 [2] 95 a2 [2] 8b bf [2] 89 be [2] 92 b8 [2] 8e bf [2] 92 90 }

  condition:
    any of them
}