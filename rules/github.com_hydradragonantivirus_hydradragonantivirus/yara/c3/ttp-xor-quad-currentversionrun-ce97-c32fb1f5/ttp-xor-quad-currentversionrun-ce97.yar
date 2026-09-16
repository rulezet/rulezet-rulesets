rule TTP_XOR_QUAD_CurrentVersionRun_ce97 {
  strings:
    $key_ce97 = { 9d f8 [2] b9 f6 [2] 92 da [2] bc f8 [2] a8 e3 [2] a7 f9 [2] b9 e4 [2] bb e5 [2] a0 e3 [2] bc e4 [2] a0 cb }

  condition:
    any of them
}