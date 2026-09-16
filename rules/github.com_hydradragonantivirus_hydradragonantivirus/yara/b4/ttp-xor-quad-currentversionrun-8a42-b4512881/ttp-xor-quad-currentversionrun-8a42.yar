rule TTP_XOR_QUAD_CurrentVersionRun_8a42 {
  strings:
    $key_8a42 = { d9 2d [2] fd 23 [2] d6 0f [2] f8 2d [2] ec 36 [2] e3 2c [2] fd 31 [2] ff 30 [2] e4 36 [2] f8 31 [2] e4 1e }

  condition:
    any of them
}