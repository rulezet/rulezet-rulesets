rule TTP_XOR_QUAD_CurrentVersionRun_80ab {
  strings:
    $key_80ab = { d3 c4 [2] f7 ca [2] dc e6 [2] f2 c4 [2] e6 df [2] e9 c5 [2] f7 d8 [2] f5 d9 [2] ee df [2] f2 d8 [2] ee f7 }

  condition:
    any of them
}