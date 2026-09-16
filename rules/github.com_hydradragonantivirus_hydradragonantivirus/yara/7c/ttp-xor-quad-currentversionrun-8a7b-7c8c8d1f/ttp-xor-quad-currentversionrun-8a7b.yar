rule TTP_XOR_QUAD_CurrentVersionRun_8a7b {
  strings:
    $key_8a7b = { d9 14 [2] fd 1a [2] d6 36 [2] f8 14 [2] ec 0f [2] e3 15 [2] fd 08 [2] ff 09 [2] e4 0f [2] f8 08 [2] e4 27 }

  condition:
    any of them
}