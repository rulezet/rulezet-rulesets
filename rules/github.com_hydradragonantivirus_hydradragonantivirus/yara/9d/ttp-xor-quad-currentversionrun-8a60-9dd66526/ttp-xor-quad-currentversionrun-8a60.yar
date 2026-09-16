rule TTP_XOR_QUAD_CurrentVersionRun_8a60 {
  strings:
    $key_8a60 = { d9 0f [2] fd 01 [2] d6 2d [2] f8 0f [2] ec 14 [2] e3 0e [2] fd 13 [2] ff 12 [2] e4 14 [2] f8 13 [2] e4 3c }

  condition:
    any of them
}