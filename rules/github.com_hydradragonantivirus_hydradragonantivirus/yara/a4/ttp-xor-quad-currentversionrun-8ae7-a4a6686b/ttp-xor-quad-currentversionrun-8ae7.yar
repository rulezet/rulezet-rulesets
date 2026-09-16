rule TTP_XOR_QUAD_CurrentVersionRun_8ae7 {
  strings:
    $key_8ae7 = { d9 88 [2] fd 86 [2] d6 aa [2] f8 88 [2] ec 93 [2] e3 89 [2] fd 94 [2] ff 95 [2] e4 93 [2] f8 94 [2] e4 bb }

  condition:
    any of them
}