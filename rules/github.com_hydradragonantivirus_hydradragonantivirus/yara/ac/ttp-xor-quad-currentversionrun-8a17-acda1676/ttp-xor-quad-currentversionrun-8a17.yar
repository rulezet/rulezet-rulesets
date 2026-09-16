rule TTP_XOR_QUAD_CurrentVersionRun_8a17 {
  strings:
    $key_8a17 = { d9 78 [2] fd 76 [2] d6 5a [2] f8 78 [2] ec 63 [2] e3 79 [2] fd 64 [2] ff 65 [2] e4 63 [2] f8 64 [2] e4 4b }

  condition:
    any of them
}