rule TTP_XOR_QUAD_CurrentVersionRun_8a05 {
  strings:
    $key_8a05 = { d9 6a [2] fd 64 [2] d6 48 [2] f8 6a [2] ec 71 [2] e3 6b [2] fd 76 [2] ff 77 [2] e4 71 [2] f8 76 [2] e4 59 }

  condition:
    any of them
}