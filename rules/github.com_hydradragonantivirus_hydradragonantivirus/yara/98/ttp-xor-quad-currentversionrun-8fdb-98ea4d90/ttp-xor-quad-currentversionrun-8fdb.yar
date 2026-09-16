rule TTP_XOR_QUAD_CurrentVersionRun_8fdb {
  strings:
    $key_8fdb = { dc b4 [2] f8 ba [2] d3 96 [2] fd b4 [2] e9 af [2] e6 b5 [2] f8 a8 [2] fa a9 [2] e1 af [2] fd a8 [2] e1 87 }

  condition:
    any of them
}