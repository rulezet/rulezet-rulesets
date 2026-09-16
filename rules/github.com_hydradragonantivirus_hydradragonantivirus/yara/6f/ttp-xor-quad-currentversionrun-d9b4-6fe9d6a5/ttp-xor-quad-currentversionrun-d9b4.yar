rule TTP_XOR_QUAD_CurrentVersionRun_d9b4 {
  strings:
    $key_d9b4 = { 8a db [2] ae d5 [2] 85 f9 [2] ab db [2] bf c0 [2] b0 da [2] ae c7 [2] ac c6 [2] b7 c0 [2] ab c7 [2] b7 e8 }

  condition:
    any of them
}