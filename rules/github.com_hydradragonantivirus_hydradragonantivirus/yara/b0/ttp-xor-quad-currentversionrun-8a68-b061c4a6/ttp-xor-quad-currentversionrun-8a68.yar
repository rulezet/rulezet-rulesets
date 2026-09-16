rule TTP_XOR_QUAD_CurrentVersionRun_8a68 {
  strings:
    $key_8a68 = { d9 07 [2] fd 09 [2] d6 25 [2] f8 07 [2] ec 1c [2] e3 06 [2] fd 1b [2] ff 1a [2] e4 1c [2] f8 1b [2] e4 34 }

  condition:
    any of them
}