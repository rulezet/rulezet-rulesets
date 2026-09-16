rule TTP_XOR_QUAD_CurrentVersionRun_8a21 {
  strings:
    $key_8a21 = { d9 4e [2] fd 40 [2] d6 6c [2] f8 4e [2] ec 55 [2] e3 4f [2] fd 52 [2] ff 53 [2] e4 55 [2] f8 52 [2] e4 7d }

  condition:
    any of them
}