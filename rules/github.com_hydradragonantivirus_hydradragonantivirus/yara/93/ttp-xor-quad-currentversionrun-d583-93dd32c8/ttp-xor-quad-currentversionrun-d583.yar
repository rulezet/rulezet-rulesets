rule TTP_XOR_QUAD_CurrentVersionRun_d583 {
  strings:
    $key_d583 = { 86 ec [2] a2 e2 [2] 89 ce [2] a7 ec [2] b3 f7 [2] bc ed [2] a2 f0 [2] a0 f1 [2] bb f7 [2] a7 f0 [2] bb df }

  condition:
    any of them
}