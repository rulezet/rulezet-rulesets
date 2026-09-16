rule TTP_XOR_QUAD_CurrentVersionRun_8a1c {
  strings:
    $key_8a1c = { d9 73 [2] fd 7d [2] d6 51 [2] f8 73 [2] ec 68 [2] e3 72 [2] fd 6f [2] ff 6e [2] e4 68 [2] f8 6f [2] e4 40 }

  condition:
    any of them
}