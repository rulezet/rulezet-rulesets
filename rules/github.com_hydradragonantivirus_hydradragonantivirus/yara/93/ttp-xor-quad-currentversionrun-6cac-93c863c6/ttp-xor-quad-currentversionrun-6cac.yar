rule TTP_XOR_QUAD_CurrentVersionRun_6cac {
  strings:
    $key_6cac = { 3f c3 [2] 1b cd [2] 30 e1 [2] 1e c3 [2] 0a d8 [2] 05 c2 [2] 1b df [2] 19 de [2] 02 d8 [2] 1e df [2] 02 f0 }

  condition:
    any of them
}