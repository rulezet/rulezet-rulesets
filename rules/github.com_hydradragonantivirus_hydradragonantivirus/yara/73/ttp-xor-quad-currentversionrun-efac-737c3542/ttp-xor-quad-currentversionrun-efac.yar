rule TTP_XOR_QUAD_CurrentVersionRun_efac {
  strings:
    $key_efac = { bc c3 [2] 98 cd [2] b3 e1 [2] 9d c3 [2] 89 d8 [2] 86 c2 [2] 98 df [2] 9a de [2] 81 d8 [2] 9d df [2] 81 f0 }

  condition:
    any of them
}