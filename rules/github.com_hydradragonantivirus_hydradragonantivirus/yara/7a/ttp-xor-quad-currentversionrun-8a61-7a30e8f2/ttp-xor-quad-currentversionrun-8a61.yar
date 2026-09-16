rule TTP_XOR_QUAD_CurrentVersionRun_8a61 {
  strings:
    $key_8a61 = { d9 0e [2] fd 00 [2] d6 2c [2] f8 0e [2] ec 15 [2] e3 0f [2] fd 12 [2] ff 13 [2] e4 15 [2] f8 12 [2] e4 3d }

  condition:
    any of them
}