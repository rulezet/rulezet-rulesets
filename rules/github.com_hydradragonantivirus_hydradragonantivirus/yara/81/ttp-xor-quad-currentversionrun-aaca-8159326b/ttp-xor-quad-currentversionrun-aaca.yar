rule TTP_XOR_QUAD_CurrentVersionRun_aaca {
  strings:
    $key_aaca = { f9 a5 [2] dd ab [2] f6 87 [2] d8 a5 [2] cc be [2] c3 a4 [2] dd b9 [2] df b8 [2] c4 be [2] d8 b9 [2] c4 96 }

  condition:
    any of them
}