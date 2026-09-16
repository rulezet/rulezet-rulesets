rule TTP_XOR_QUAD_CurrentVersionRun_2fac {
  strings:
    $key_2fac = { 7c c3 [2] 58 cd [2] 73 e1 [2] 5d c3 [2] 49 d8 [2] 46 c2 [2] 58 df [2] 5a de [2] 41 d8 [2] 5d df [2] 41 f0 }

  condition:
    any of them
}