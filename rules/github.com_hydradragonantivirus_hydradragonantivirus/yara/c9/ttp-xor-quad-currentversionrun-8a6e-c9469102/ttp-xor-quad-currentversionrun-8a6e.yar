rule TTP_XOR_QUAD_CurrentVersionRun_8a6e {
  strings:
    $key_8a6e = { d9 01 [2] fd 0f [2] d6 23 [2] f8 01 [2] ec 1a [2] e3 00 [2] fd 1d [2] ff 1c [2] e4 1a [2] f8 1d [2] e4 32 }

  condition:
    any of them
}