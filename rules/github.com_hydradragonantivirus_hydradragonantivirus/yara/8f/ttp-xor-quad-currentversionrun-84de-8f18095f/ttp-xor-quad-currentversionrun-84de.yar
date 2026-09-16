rule TTP_XOR_QUAD_CurrentVersionRun_84de {
  strings:
    $key_84de = { d7 b1 [2] f3 bf [2] d8 93 [2] f6 b1 [2] e2 aa [2] ed b0 [2] f3 ad [2] f1 ac [2] ea aa [2] f6 ad [2] ea 82 }

  condition:
    any of them
}