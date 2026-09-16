rule TTP_XOR_QUAD_CurrentVersionRun_8a23 {
  strings:
    $key_8a23 = { d9 4c [2] fd 42 [2] d6 6e [2] f8 4c [2] ec 57 [2] e3 4d [2] fd 50 [2] ff 51 [2] e4 57 [2] f8 50 [2] e4 7f }

  condition:
    any of them
}