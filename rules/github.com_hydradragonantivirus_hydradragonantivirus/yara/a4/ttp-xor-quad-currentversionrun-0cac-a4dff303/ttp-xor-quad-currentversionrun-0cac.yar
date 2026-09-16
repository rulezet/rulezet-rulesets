rule TTP_XOR_QUAD_CurrentVersionRun_0cac {
  strings:
    $key_0cac = { 5f c3 [2] 7b cd [2] 50 e1 [2] 7e c3 [2] 6a d8 [2] 65 c2 [2] 7b df [2] 79 de [2] 62 d8 [2] 7e df [2] 62 f0 }

  condition:
    any of them
}