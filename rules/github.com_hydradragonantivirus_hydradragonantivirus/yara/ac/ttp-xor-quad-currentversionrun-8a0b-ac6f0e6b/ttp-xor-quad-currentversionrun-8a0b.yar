rule TTP_XOR_QUAD_CurrentVersionRun_8a0b {
  strings:
    $key_8a0b = { d9 64 [2] fd 6a [2] d6 46 [2] f8 64 [2] ec 7f [2] e3 65 [2] fd 78 [2] ff 79 [2] e4 7f [2] f8 78 [2] e4 57 }

  condition:
    any of them
}