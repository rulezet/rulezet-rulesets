rule TTP_XOR_QUAD_CurrentVersionRun_8fda {
  strings:
    $key_8fda = { dc b5 [2] f8 bb [2] d3 97 [2] fd b5 [2] e9 ae [2] e6 b4 [2] f8 a9 [2] fa a8 [2] e1 ae [2] fd a9 [2] e1 86 }

  condition:
    any of them
}