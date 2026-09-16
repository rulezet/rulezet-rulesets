rule TTP_XOR_QUAD_CurrentVersionRun_8a2b {
  strings:
    $key_8a2b = { d9 44 [2] fd 4a [2] d6 66 [2] f8 44 [2] ec 5f [2] e3 45 [2] fd 58 [2] ff 59 [2] e4 5f [2] f8 58 [2] e4 77 }

  condition:
    any of them
}