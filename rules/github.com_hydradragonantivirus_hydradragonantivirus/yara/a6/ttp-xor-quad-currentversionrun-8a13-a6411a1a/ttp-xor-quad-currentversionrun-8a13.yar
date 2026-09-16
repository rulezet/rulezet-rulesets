rule TTP_XOR_QUAD_CurrentVersionRun_8a13 {
  strings:
    $key_8a13 = { d9 7c [2] fd 72 [2] d6 5e [2] f8 7c [2] ec 67 [2] e3 7d [2] fd 60 [2] ff 61 [2] e4 67 [2] f8 60 [2] e4 4f }

  condition:
    any of them
}