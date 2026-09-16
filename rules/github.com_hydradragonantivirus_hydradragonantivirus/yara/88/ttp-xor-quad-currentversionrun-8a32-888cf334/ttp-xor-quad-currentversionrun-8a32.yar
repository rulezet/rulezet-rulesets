rule TTP_XOR_QUAD_CurrentVersionRun_8a32 {
  strings:
    $key_8a32 = { d9 5d [2] fd 53 [2] d6 7f [2] f8 5d [2] ec 46 [2] e3 5c [2] fd 41 [2] ff 40 [2] e4 46 [2] f8 41 [2] e4 6e }

  condition:
    any of them
}