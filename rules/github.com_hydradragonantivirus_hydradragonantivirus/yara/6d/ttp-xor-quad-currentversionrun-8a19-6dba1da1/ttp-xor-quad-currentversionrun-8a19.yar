rule TTP_XOR_QUAD_CurrentVersionRun_8a19 {
  strings:
    $key_8a19 = { d9 76 [2] fd 78 [2] d6 54 [2] f8 76 [2] ec 6d [2] e3 77 [2] fd 6a [2] ff 6b [2] e4 6d [2] f8 6a [2] e4 45 }

  condition:
    any of them
}