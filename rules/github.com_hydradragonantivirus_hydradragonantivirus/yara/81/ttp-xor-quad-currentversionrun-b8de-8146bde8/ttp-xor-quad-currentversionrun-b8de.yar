rule TTP_XOR_QUAD_CurrentVersionRun_b8de {
  strings:
    $key_b8de = { eb b1 [2] cf bf [2] e4 93 [2] ca b1 [2] de aa [2] d1 b0 [2] cf ad [2] cd ac [2] d6 aa [2] ca ad [2] d6 82 }

  condition:
    any of them
}