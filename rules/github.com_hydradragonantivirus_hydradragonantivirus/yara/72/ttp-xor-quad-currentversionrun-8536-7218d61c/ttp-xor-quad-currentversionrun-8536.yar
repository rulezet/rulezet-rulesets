rule TTP_XOR_QUAD_CurrentVersionRun_8536 {
  strings:
    $key_8536 = { d6 59 [2] f2 57 [2] d9 7b [2] f7 59 [2] e3 42 [2] ec 58 [2] f2 45 [2] f0 44 [2] eb 42 [2] f7 45 [2] eb 6a }

  condition:
    any of them
}