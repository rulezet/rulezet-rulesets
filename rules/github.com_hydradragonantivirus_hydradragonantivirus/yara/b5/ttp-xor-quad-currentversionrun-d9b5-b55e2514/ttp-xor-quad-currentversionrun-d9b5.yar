rule TTP_XOR_QUAD_CurrentVersionRun_d9b5 {
  strings:
    $key_d9b5 = { 8a da [2] ae d4 [2] 85 f8 [2] ab da [2] bf c1 [2] b0 db [2] ae c6 [2] ac c7 [2] b7 c1 [2] ab c6 [2] b7 e9 }

  condition:
    any of them
}