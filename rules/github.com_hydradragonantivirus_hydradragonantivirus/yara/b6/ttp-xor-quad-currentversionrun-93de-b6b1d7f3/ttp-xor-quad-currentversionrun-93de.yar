rule TTP_XOR_QUAD_CurrentVersionRun_93de {
  strings:
    $key_93de = { c0 b1 [2] e4 bf [2] cf 93 [2] e1 b1 [2] f5 aa [2] fa b0 [2] e4 ad [2] e6 ac [2] fd aa [2] e1 ad [2] fd 82 }

  condition:
    any of them
}