rule TTP_XOR_QUAD_CurrentVersionRun_a9ce {
  strings:
    $key_a9ce = { fa a1 [2] de af [2] f5 83 [2] db a1 [2] cf ba [2] c0 a0 [2] de bd [2] dc bc [2] c7 ba [2] db bd [2] c7 92 }

  condition:
    any of them
}