rule TTP_XOR_QUAD_CurrentVersionRun_8a1b {
  strings:
    $key_8a1b = { d9 74 [2] fd 7a [2] d6 56 [2] f8 74 [2] ec 6f [2] e3 75 [2] fd 68 [2] ff 69 [2] e4 6f [2] f8 68 [2] e4 47 }

  condition:
    any of them
}