rule TTP_XOR_QUAD_CurrentVersionRun_ecac {
  strings:
    $key_ecac = { bf c3 [2] 9b cd [2] b0 e1 [2] 9e c3 [2] 8a d8 [2] 85 c2 [2] 9b df [2] 99 de [2] 82 d8 [2] 9e df [2] 82 f0 }

  condition:
    any of them
}