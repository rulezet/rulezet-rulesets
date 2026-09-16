rule TTP_XOR_QUAD_CurrentVersionRun_8afd {
  strings:
    $key_8afd = { d9 92 [2] fd 9c [2] d6 b0 [2] f8 92 [2] ec 89 [2] e3 93 [2] fd 8e [2] ff 8f [2] e4 89 [2] f8 8e [2] e4 a1 }

  condition:
    any of them
}