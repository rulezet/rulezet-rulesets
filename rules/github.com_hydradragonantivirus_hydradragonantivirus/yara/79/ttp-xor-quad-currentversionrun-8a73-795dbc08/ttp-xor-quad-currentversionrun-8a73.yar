rule TTP_XOR_QUAD_CurrentVersionRun_8a73 {
  strings:
    $key_8a73 = { d9 1c [2] fd 12 [2] d6 3e [2] f8 1c [2] ec 07 [2] e3 1d [2] fd 00 [2] ff 01 [2] e4 07 [2] f8 00 [2] e4 2f }

  condition:
    any of them
}