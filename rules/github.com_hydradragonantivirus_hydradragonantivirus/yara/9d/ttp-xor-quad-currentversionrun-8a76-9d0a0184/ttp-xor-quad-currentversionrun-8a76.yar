rule TTP_XOR_QUAD_CurrentVersionRun_8a76 {
  strings:
    $key_8a76 = { d9 19 [2] fd 17 [2] d6 3b [2] f8 19 [2] ec 02 [2] e3 18 [2] fd 05 [2] ff 04 [2] e4 02 [2] f8 05 [2] e4 2a }

  condition:
    any of them
}