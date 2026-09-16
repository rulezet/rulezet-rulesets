rule TTP_XOR_QUAD_CurrentVersionRun_8a08 {
  strings:
    $key_8a08 = { d9 67 [2] fd 69 [2] d6 45 [2] f8 67 [2] ec 7c [2] e3 66 [2] fd 7b [2] ff 7a [2] e4 7c [2] f8 7b [2] e4 54 }

  condition:
    any of them
}