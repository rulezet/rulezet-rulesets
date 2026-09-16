rule TTP_XOR_QUAD_CurrentVersionRun_85de {
  strings:
    $key_85de = { d6 b1 [2] f2 bf [2] d9 93 [2] f7 b1 [2] e3 aa [2] ec b0 [2] f2 ad [2] f0 ac [2] eb aa [2] f7 ad [2] eb 82 }

  condition:
    any of them
}