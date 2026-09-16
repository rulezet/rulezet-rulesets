rule TTP_XOR_QUAD_CurrentVersionRun_8fcb {
  strings:
    $key_8fcb = { dc a4 [2] f8 aa [2] d3 86 [2] fd a4 [2] e9 bf [2] e6 a5 [2] f8 b8 [2] fa b9 [2] e1 bf [2] fd b8 [2] e1 97 }

  condition:
    any of them
}