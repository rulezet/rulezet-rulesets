rule TTP_XOR_QUAD_CurrentVersionRun_a9de {
  strings:
    $key_a9de = { fa b1 [2] de bf [2] f5 93 [2] db b1 [2] cf aa [2] c0 b0 [2] de ad [2] dc ac [2] c7 aa [2] db ad [2] c7 82 }

  condition:
    any of them
}