rule TTP_XOR_QUAD_CurrentVersionRun_8af5 {
  strings:
    $key_8af5 = { d9 9a [2] fd 94 [2] d6 b8 [2] f8 9a [2] ec 81 [2] e3 9b [2] fd 86 [2] ff 87 [2] e4 81 [2] f8 86 [2] e4 a9 }

  condition:
    any of them
}