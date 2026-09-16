rule TTP_XOR_QUAD_CurrentVersionRun_8a35 {
  strings:
    $key_8a35 = { d9 5a [2] fd 54 [2] d6 78 [2] f8 5a [2] ec 41 [2] e3 5b [2] fd 46 [2] ff 47 [2] e4 41 [2] f8 46 [2] e4 69 }

  condition:
    any of them
}