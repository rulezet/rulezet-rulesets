rule TTP_XOR_QUAD_CurrentVersionRun_8af4 {
  strings:
    $key_8af4 = { d9 9b [2] fd 95 [2] d6 b9 [2] f8 9b [2] ec 80 [2] e3 9a [2] fd 87 [2] ff 86 [2] e4 80 [2] f8 87 [2] e4 a8 }

  condition:
    any of them
}