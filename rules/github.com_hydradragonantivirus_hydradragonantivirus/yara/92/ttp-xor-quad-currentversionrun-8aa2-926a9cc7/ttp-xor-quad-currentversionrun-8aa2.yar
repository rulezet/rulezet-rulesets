rule TTP_XOR_QUAD_CurrentVersionRun_8aa2 {
  strings:
    $key_8aa2 = { d9 cd [2] fd c3 [2] d6 ef [2] f8 cd [2] ec d6 [2] e3 cc [2] fd d1 [2] ff d0 [2] e4 d6 [2] f8 d1 [2] e4 fe }

  condition:
    any of them
}