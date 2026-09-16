rule TTP_XOR_QUAD_CurrentVersionRun_8a5d {
  strings:
    $key_8a5d = { d9 32 [2] fd 3c [2] d6 10 [2] f8 32 [2] ec 29 [2] e3 33 [2] fd 2e [2] ff 2f [2] e4 29 [2] f8 2e [2] e4 01 }

  condition:
    any of them
}