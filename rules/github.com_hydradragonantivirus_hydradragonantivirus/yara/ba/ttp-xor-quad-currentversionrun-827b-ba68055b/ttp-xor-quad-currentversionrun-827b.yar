rule TTP_XOR_QUAD_CurrentVersionRun_827b {
  strings:
    $key_827b = { d1 14 [2] f5 1a [2] de 36 [2] f0 14 [2] e4 0f [2] eb 15 [2] f5 08 [2] f7 09 [2] ec 0f [2] f0 08 [2] ec 27 }

  condition:
    any of them
}