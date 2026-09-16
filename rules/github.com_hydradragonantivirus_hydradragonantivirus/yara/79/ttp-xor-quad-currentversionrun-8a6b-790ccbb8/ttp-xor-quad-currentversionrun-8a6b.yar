rule TTP_XOR_QUAD_CurrentVersionRun_8a6b {
  strings:
    $key_8a6b = { d9 04 [2] fd 0a [2] d6 26 [2] f8 04 [2] ec 1f [2] e3 05 [2] fd 18 [2] ff 19 [2] e4 1f [2] f8 18 [2] e4 37 }

  condition:
    any of them
}