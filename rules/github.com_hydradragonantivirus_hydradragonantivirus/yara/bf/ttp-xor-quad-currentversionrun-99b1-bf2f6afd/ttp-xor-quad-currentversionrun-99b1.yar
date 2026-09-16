rule TTP_XOR_QUAD_CurrentVersionRun_99b1 {
  strings:
    $key_99b1 = { ca de [2] ee d0 [2] c5 fc [2] eb de [2] ff c5 [2] f0 df [2] ee c2 [2] ec c3 [2] f7 c5 [2] eb c2 [2] f7 ed }

  condition:
    any of them
}