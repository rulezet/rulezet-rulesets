rule TTP_XOR_QUAD_CurrentVersionRun_8a25 {
  strings:
    $key_8a25 = { d9 4a [2] fd 44 [2] d6 68 [2] f8 4a [2] ec 51 [2] e3 4b [2] fd 56 [2] ff 57 [2] e4 51 [2] f8 56 [2] e4 79 }

  condition:
    any of them
}