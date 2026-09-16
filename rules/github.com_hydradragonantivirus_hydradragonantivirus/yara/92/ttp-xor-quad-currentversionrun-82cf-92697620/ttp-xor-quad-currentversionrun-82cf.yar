rule TTP_XOR_QUAD_CurrentVersionRun_82cf {
  strings:
    $key_82cf = { d1 a0 [2] f5 ae [2] de 82 [2] f0 a0 [2] e4 bb [2] eb a1 [2] f5 bc [2] f7 bd [2] ec bb [2] f0 bc [2] ec 93 }

  condition:
    any of them
}