rule TTP_XOR_QUAD_CurrentVersionRun_4fac {
  strings:
    $key_4fac = { 1c c3 [2] 38 cd [2] 13 e1 [2] 3d c3 [2] 29 d8 [2] 26 c2 [2] 38 df [2] 3a de [2] 21 d8 [2] 3d df [2] 21 f0 }

  condition:
    any of them
}