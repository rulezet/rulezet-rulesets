rule TTP_XOR_QUAD_CurrentVersionRun_8bde {
  strings:
    $key_8bde = { d8 b1 [2] fc bf [2] d7 93 [2] f9 b1 [2] ed aa [2] e2 b0 [2] fc ad [2] fe ac [2] e5 aa [2] f9 ad [2] e5 82 }

  condition:
    any of them
}