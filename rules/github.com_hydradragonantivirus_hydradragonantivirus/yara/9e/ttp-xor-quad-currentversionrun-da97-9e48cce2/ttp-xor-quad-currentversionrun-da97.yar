rule TTP_XOR_QUAD_CurrentVersionRun_da97 {
  strings:
    $key_da97 = { 89 f8 [2] ad f6 [2] 86 da [2] a8 f8 [2] bc e3 [2] b3 f9 [2] ad e4 [2] af e5 [2] b4 e3 [2] a8 e4 [2] b4 cb }

  condition:
    any of them
}