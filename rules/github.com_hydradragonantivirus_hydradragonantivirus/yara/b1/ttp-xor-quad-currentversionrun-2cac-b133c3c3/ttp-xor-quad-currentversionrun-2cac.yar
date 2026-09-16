rule TTP_XOR_QUAD_CurrentVersionRun_2cac {
  strings:
    $key_2cac = { 7f c3 [2] 5b cd [2] 70 e1 [2] 5e c3 [2] 4a d8 [2] 45 c2 [2] 5b df [2] 59 de [2] 42 d8 [2] 5e df [2] 42 f0 }

  condition:
    any of them
}