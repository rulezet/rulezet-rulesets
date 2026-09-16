rule TTP_XOR_QUAD_CurrentVersionRun_8266 {
  strings:
    $key_8266 = { d1 09 [2] f5 07 [2] de 2b [2] f0 09 [2] e4 12 [2] eb 08 [2] f5 15 [2] f7 14 [2] ec 12 [2] f0 15 [2] ec 3a }

  condition:
    any of them
}