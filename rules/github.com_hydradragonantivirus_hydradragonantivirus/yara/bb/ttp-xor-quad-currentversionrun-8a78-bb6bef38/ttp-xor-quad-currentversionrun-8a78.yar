rule TTP_XOR_QUAD_CurrentVersionRun_8a78 {
  strings:
    $key_8a78 = { d9 17 [2] fd 19 [2] d6 35 [2] f8 17 [2] ec 0c [2] e3 16 [2] fd 0b [2] ff 0a [2] e4 0c [2] f8 0b [2] e4 24 }

  condition:
    any of them
}