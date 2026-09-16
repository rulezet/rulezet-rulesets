rule TTP_XOR_QUAD_CurrentVersionRun_8a38 {
  strings:
    $key_8a38 = { d9 57 [2] fd 59 [2] d6 75 [2] f8 57 [2] ec 4c [2] e3 56 [2] fd 4b [2] ff 4a [2] e4 4c [2] f8 4b [2] e4 64 }

  condition:
    any of them
}