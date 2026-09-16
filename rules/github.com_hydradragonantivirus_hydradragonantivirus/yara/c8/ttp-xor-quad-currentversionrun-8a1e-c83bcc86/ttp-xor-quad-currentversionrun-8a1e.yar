rule TTP_XOR_QUAD_CurrentVersionRun_8a1e {
  strings:
    $key_8a1e = { d9 71 [2] fd 7f [2] d6 53 [2] f8 71 [2] ec 6a [2] e3 70 [2] fd 6d [2] ff 6c [2] e4 6a [2] f8 6d [2] e4 42 }

  condition:
    any of them
}