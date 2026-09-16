rule TTP_XOR_QUAD_CurrentVersionRun_85a2 {
  strings:
    $key_85a2 = { d6 cd [2] f2 c3 [2] d9 ef [2] f7 cd [2] e3 d6 [2] ec cc [2] f2 d1 [2] f0 d0 [2] eb d6 [2] f7 d1 [2] eb fe }

  condition:
    any of them
}