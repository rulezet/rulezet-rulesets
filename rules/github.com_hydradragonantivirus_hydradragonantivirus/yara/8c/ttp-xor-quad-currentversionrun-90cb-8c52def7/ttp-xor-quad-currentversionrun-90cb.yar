rule TTP_XOR_QUAD_CurrentVersionRun_90cb {
  strings:
    $key_90cb = { c3 a4 [2] e7 aa [2] cc 86 [2] e2 a4 [2] f6 bf [2] f9 a5 [2] e7 b8 [2] e5 b9 [2] fe bf [2] e2 b8 [2] fe 97 }

  condition:
    any of them
}