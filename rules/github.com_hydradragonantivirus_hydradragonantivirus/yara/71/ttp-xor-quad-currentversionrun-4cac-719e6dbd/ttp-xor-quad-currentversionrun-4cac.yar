rule TTP_XOR_QUAD_CurrentVersionRun_4cac {
  strings:
    $key_4cac = { 1f c3 [2] 3b cd [2] 10 e1 [2] 3e c3 [2] 2a d8 [2] 25 c2 [2] 3b df [2] 39 de [2] 22 d8 [2] 3e df [2] 22 f0 }

  condition:
    any of them
}