rule TTP_XOR_QUAD_CurrentVersionRun_95be {
  strings:
    $key_95be = { c6 d1 [2] e2 df [2] c9 f3 [2] e7 d1 [2] f3 ca [2] fc d0 [2] e2 cd [2] e0 cc [2] fb ca [2] e7 cd [2] fb e2 }

  condition:
    any of them
}