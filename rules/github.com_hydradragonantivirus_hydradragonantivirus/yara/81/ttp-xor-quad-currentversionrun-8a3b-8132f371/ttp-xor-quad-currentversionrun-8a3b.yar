rule TTP_XOR_QUAD_CurrentVersionRun_8a3b {
  strings:
    $key_8a3b = { d9 54 [2] fd 5a [2] d6 76 [2] f8 54 [2] ec 4f [2] e3 55 [2] fd 48 [2] ff 49 [2] e4 4f [2] f8 48 [2] e4 67 }

  condition:
    any of them
}