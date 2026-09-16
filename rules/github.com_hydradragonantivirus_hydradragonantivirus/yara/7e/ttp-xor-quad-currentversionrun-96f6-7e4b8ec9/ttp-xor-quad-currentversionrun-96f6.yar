rule TTP_XOR_QUAD_CurrentVersionRun_96f6 {
  strings:
    $key_96f6 = { c5 99 [2] e1 97 [2] ca bb [2] e4 99 [2] f0 82 [2] ff 98 [2] e1 85 [2] e3 84 [2] f8 82 [2] e4 85 [2] f8 aa }

  condition:
    any of them
}