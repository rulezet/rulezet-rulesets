rule TTP_XOR_QUAD_CurrentVersionRun_dcad {
  strings:
    $key_dcad = { 8f c2 [2] ab cc [2] 80 e0 [2] ae c2 [2] ba d9 [2] b5 c3 [2] ab de [2] a9 df [2] b2 d9 [2] ae de [2] b2 f1 }

  condition:
    any of them
}