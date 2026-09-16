rule TTP_XOR_QUAD_CurrentVersionRun_8a06 {
  strings:
    $key_8a06 = { d9 69 [2] fd 67 [2] d6 4b [2] f8 69 [2] ec 72 [2] e3 68 [2] fd 75 [2] ff 74 [2] e4 72 [2] f8 75 [2] e4 5a }

  condition:
    any of them
}