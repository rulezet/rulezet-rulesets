rule TTP_XOR_QUAD_CurrentVersionRun_8a22 {
  strings:
    $key_8a22 = { d9 4d [2] fd 43 [2] d6 6f [2] f8 4d [2] ec 56 [2] e3 4c [2] fd 51 [2] ff 50 [2] e4 56 [2] f8 51 [2] e4 7e }

  condition:
    any of them
}