rule TTP_XOR_QUAD_CurrentVersionRun_8a16 {
  strings:
    $key_8a16 = { d9 79 [2] fd 77 [2] d6 5b [2] f8 79 [2] ec 62 [2] e3 78 [2] fd 65 [2] ff 64 [2] e4 62 [2] f8 65 [2] e4 4a }

  condition:
    any of them
}