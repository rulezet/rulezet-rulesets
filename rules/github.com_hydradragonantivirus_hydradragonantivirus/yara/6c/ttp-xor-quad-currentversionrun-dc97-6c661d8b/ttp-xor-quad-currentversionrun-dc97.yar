rule TTP_XOR_QUAD_CurrentVersionRun_dc97 {
  strings:
    $key_dc97 = { 8f f8 [2] ab f6 [2] 80 da [2] ae f8 [2] ba e3 [2] b5 f9 [2] ab e4 [2] a9 e5 [2] b2 e3 [2] ae e4 [2] b2 cb }

  condition:
    any of them
}