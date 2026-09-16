rule TTP_XOR_QUAD_CurrentVersionRun_aadb {
  strings:
    $key_aadb = { f9 b4 [2] dd ba [2] f6 96 [2] d8 b4 [2] cc af [2] c3 b5 [2] dd a8 [2] df a9 [2] c4 af [2] d8 a8 [2] c4 87 }

  condition:
    any of them
}