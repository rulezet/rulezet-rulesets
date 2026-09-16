rule TTP_XOR_QUAD_CurrentVersionRun_c9de {
  strings:
    $key_c9de = { 9a b1 [2] be bf [2] 95 93 [2] bb b1 [2] af aa [2] a0 b0 [2] be ad [2] bc ac [2] a7 aa [2] bb ad [2] a7 82 }

  condition:
    any of them
}