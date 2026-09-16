rule TTP_XOR_QUAD_CurrentVersionRun_8ebe {
  strings:
    $key_8ebe = { dd d1 [2] f9 df [2] d2 f3 [2] fc d1 [2] e8 ca [2] e7 d0 [2] f9 cd [2] fb cc [2] e0 ca [2] fc cd [2] e0 e2 }

  condition:
    any of them
}