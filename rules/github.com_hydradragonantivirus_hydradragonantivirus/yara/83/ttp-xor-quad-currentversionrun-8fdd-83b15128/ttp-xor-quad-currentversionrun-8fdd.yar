rule TTP_XOR_QUAD_CurrentVersionRun_8fdd {
  strings:
    $key_8fdd = { dc b2 [2] f8 bc [2] d3 90 [2] fd b2 [2] e9 a9 [2] e6 b3 [2] f8 ae [2] fa af [2] e1 a9 [2] fd ae [2] e1 81 }

  condition:
    any of them
}