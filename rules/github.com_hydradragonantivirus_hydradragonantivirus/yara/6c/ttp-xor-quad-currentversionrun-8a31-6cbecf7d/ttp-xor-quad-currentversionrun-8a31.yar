rule TTP_XOR_QUAD_CurrentVersionRun_8a31 {
  strings:
    $key_8a31 = { d9 5e [2] fd 50 [2] d6 7c [2] f8 5e [2] ec 45 [2] e3 5f [2] fd 42 [2] ff 43 [2] e4 45 [2] f8 42 [2] e4 6d }

  condition:
    any of them
}