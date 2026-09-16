rule TTP_XOR_QUAD_CurrentVersionRun_90de {
  strings:
    $key_90de = { c3 b1 [2] e7 bf [2] cc 93 [2] e2 b1 [2] f6 aa [2] f9 b0 [2] e7 ad [2] e5 ac [2] fe aa [2] e2 ad [2] fe 82 }

  condition:
    any of them
}