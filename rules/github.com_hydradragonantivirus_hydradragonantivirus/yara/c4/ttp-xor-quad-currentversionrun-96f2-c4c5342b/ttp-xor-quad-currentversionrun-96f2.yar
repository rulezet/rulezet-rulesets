rule TTP_XOR_QUAD_CurrentVersionRun_96f2 {
  strings:
    $key_96f2 = { c5 9d [2] e1 93 [2] ca bf [2] e4 9d [2] f0 86 [2] ff 9c [2] e1 81 [2] e3 80 [2] f8 86 [2] e4 81 [2] f8 ae }

  condition:
    any of them
}