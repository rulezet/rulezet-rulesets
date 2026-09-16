rule TTP_XOR_QUAD_CurrentVersionRun_ffac {
  strings:
    $key_ffac = { ac c3 [2] 88 cd [2] a3 e1 [2] 8d c3 [2] 99 d8 [2] 96 c2 [2] 88 df [2] 8a de [2] 91 d8 [2] 8d df [2] 91 f0 }

  condition:
    any of them
}