rule TTP_XOR_QUAD_CurrentVersionRun_8bbc {
  strings:
    $key_8bbc = { d8 d3 [2] fc dd [2] d7 f1 [2] f9 d3 [2] ed c8 [2] e2 d2 [2] fc cf [2] fe ce [2] e5 c8 [2] f9 cf [2] e5 e0 }

  condition:
    any of them
}