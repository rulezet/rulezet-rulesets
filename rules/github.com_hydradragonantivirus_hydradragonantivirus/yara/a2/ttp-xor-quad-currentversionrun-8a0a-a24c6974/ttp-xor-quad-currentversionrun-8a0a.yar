rule TTP_XOR_QUAD_CurrentVersionRun_8a0a {
  strings:
    $key_8a0a = { d9 65 [2] fd 6b [2] d6 47 [2] f8 65 [2] ec 7e [2] e3 64 [2] fd 79 [2] ff 78 [2] e4 7e [2] f8 79 [2] e4 56 }

  condition:
    any of them
}