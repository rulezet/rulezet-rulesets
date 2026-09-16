rule TTP_XOR_QUAD_CurrentVersionRun_8aa7 {
  strings:
    $key_8aa7 = { d9 c8 [2] fd c6 [2] d6 ea [2] f8 c8 [2] ec d3 [2] e3 c9 [2] fd d4 [2] ff d5 [2] e4 d3 [2] f8 d4 [2] e4 fb }

  condition:
    any of them
}