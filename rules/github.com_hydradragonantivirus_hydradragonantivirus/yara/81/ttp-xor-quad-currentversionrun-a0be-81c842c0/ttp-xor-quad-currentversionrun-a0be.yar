rule TTP_XOR_QUAD_CurrentVersionRun_a0be {
  strings:
    $key_a0be = { f3 d1 [2] d7 df [2] fc f3 [2] d2 d1 [2] c6 ca [2] c9 d0 [2] d7 cd [2] d5 cc [2] ce ca [2] d2 cd [2] ce e2 }

  condition:
    any of them
}