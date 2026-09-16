rule TTP_XOR_QUAD_CurrentVersionRun_8abb {
  strings:
    $key_8abb = { d9 d4 [2] fd da [2] d6 f6 [2] f8 d4 [2] ec cf [2] e3 d5 [2] fd c8 [2] ff c9 [2] e4 cf [2] f8 c8 [2] e4 e7 }

  condition:
    any of them
}