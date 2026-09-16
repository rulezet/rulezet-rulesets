rule TTP_XOR_QUAD_CurrentVersionRun_8a3a {
  strings:
    $key_8a3a = { d9 55 [2] fd 5b [2] d6 77 [2] f8 55 [2] ec 4e [2] e3 54 [2] fd 49 [2] ff 48 [2] e4 4e [2] f8 49 [2] e4 66 }

  condition:
    any of them
}