rule TTP_XOR_QUAD_CurrentVersionRun_8a3e {
  strings:
    $key_8a3e = { d9 51 [2] fd 5f [2] d6 73 [2] f8 51 [2] ec 4a [2] e3 50 [2] fd 4d [2] ff 4c [2] e4 4a [2] f8 4d [2] e4 62 }

  condition:
    any of them
}