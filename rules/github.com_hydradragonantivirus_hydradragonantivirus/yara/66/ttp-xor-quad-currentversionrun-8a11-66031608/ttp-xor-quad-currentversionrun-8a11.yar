rule TTP_XOR_QUAD_CurrentVersionRun_8a11 {
  strings:
    $key_8a11 = { d9 7e [2] fd 70 [2] d6 5c [2] f8 7e [2] ec 65 [2] e3 7f [2] fd 62 [2] ff 63 [2] e4 65 [2] f8 62 [2] e4 4d }

  condition:
    any of them
}