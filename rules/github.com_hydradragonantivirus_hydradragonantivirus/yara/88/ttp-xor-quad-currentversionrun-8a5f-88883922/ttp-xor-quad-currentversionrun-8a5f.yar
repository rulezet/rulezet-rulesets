rule TTP_XOR_QUAD_CurrentVersionRun_8a5f {
  strings:
    $key_8a5f = { d9 30 [2] fd 3e [2] d6 12 [2] f8 30 [2] ec 2b [2] e3 31 [2] fd 2c [2] ff 2d [2] e4 2b [2] f8 2c [2] e4 03 }

  condition:
    any of them
}