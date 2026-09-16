rule TTP_XOR_QUAD_CurrentVersionRun_8a2d {
  strings:
    $key_8a2d = { d9 42 [2] fd 4c [2] d6 60 [2] f8 42 [2] ec 59 [2] e3 43 [2] fd 5e [2] ff 5f [2] e4 59 [2] f8 5e [2] e4 71 }

  condition:
    any of them
}