rule TTP_XOR_QUAD_CurrentVersionRun_bede {
  strings:
    $key_bede = { ed b1 [2] c9 bf [2] e2 93 [2] cc b1 [2] d8 aa [2] d7 b0 [2] c9 ad [2] cb ac [2] d0 aa [2] cc ad [2] d0 82 }

  condition:
    any of them
}