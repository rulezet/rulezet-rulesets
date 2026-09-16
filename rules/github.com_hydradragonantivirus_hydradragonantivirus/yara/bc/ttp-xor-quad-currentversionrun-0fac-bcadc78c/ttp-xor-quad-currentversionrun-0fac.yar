rule TTP_XOR_QUAD_CurrentVersionRun_0fac {
  strings:
    $key_0fac = { 5c c3 [2] 78 cd [2] 53 e1 [2] 7d c3 [2] 69 d8 [2] 66 c2 [2] 78 df [2] 7a de [2] 61 d8 [2] 7d df [2] 61 f0 }

  condition:
    any of them
}