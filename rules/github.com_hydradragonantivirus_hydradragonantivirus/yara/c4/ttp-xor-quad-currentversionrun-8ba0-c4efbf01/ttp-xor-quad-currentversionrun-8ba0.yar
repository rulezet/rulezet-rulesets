rule TTP_XOR_QUAD_CurrentVersionRun_8ba0 {
  strings:
    $key_8ba0 = { d8 cf [2] fc c1 [2] d7 ed [2] f9 cf [2] ed d4 [2] e2 ce [2] fc d3 [2] fe d2 [2] e5 d4 [2] f9 d3 [2] e5 fc }

  condition:
    any of them
}