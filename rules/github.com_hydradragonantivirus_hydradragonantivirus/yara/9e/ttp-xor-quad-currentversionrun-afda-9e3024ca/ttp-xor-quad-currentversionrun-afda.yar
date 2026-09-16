rule TTP_XOR_QUAD_CurrentVersionRun_afda {
  strings:
    $key_afda = { fc b5 [2] d8 bb [2] f3 97 [2] dd b5 [2] c9 ae [2] c6 b4 [2] d8 a9 [2] da a8 [2] c1 ae [2] dd a9 [2] c1 86 }

  condition:
    any of them
}