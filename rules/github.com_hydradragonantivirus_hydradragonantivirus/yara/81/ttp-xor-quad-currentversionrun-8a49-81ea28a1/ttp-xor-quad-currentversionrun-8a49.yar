rule TTP_XOR_QUAD_CurrentVersionRun_8a49 {
  strings:
    $key_8a49 = { d9 26 [2] fd 28 [2] d6 04 [2] f8 26 [2] ec 3d [2] e3 27 [2] fd 3a [2] ff 3b [2] e4 3d [2] f8 3a [2] e4 15 }

  condition:
    any of them
}