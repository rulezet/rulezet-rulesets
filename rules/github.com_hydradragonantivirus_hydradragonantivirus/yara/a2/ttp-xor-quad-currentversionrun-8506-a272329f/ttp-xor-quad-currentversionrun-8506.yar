rule TTP_XOR_QUAD_CurrentVersionRun_8506 {
  strings:
    $key_8506 = { d6 69 [2] f2 67 [2] d9 4b [2] f7 69 [2] e3 72 [2] ec 68 [2] f2 75 [2] f0 74 [2] eb 72 [2] f7 75 [2] eb 5a }

  condition:
    any of them
}