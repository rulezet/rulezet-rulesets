rule TTP_XOR_QUAD_CurrentVersionRun_89de {
  strings:
    $key_89de = { da b1 [2] fe bf [2] d5 93 [2] fb b1 [2] ef aa [2] e0 b0 [2] fe ad [2] fc ac [2] e7 aa [2] fb ad [2] e7 82 }

  condition:
    any of them
}