rule TTP_XOR_QUAD_CurrentVersionRun_8a9d {
  strings:
    $key_8a9d = { d9 f2 [2] fd fc [2] d6 d0 [2] f8 f2 [2] ec e9 [2] e3 f3 [2] fd ee [2] ff ef [2] e4 e9 [2] f8 ee [2] e4 c1 }

  condition:
    any of them
}