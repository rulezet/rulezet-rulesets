rule TTP_XOR_QUAD_CurrentVersionRun_8a2e {
  strings:
    $key_8a2e = { d9 41 [2] fd 4f [2] d6 63 [2] f8 41 [2] ec 5a [2] e3 40 [2] fd 5d [2] ff 5c [2] e4 5a [2] f8 5d [2] e4 72 }

  condition:
    any of them
}