rule TTP_XOR_QUAD_CurrentVersionRun_91de {
  strings:
    $key_91de = { c2 b1 [2] e6 bf [2] cd 93 [2] e3 b1 [2] f7 aa [2] f8 b0 [2] e6 ad [2] e4 ac [2] ff aa [2] e3 ad [2] ff 82 }

  condition:
    any of them
}