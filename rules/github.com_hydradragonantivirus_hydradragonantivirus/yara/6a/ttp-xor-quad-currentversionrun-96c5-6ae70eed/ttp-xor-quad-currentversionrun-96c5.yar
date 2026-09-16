rule TTP_XOR_QUAD_CurrentVersionRun_96c5 {
  strings:
    $key_96c5 = { c5 aa [2] e1 a4 [2] ca 88 [2] e4 aa [2] f0 b1 [2] ff ab [2] e1 b6 [2] e3 b7 [2] f8 b1 [2] e4 b6 [2] f8 99 }

  condition:
    any of them
}