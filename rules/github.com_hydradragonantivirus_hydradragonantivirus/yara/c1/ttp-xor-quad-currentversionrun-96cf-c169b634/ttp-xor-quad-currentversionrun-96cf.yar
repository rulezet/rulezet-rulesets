rule TTP_XOR_QUAD_CurrentVersionRun_96cf {
  strings:
    $key_96cf = { c5 a0 [2] e1 ae [2] ca 82 [2] e4 a0 [2] f0 bb [2] ff a1 [2] e1 bc [2] e3 bd [2] f8 bb [2] e4 bc [2] f8 93 }

  condition:
    any of them
}