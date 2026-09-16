rule TTP_XOR_QUAD_CurrentVersionRun_dfde {
  strings:
    $key_dfde = { 8c b1 [2] a8 bf [2] 83 93 [2] ad b1 [2] b9 aa [2] b6 b0 [2] a8 ad [2] aa ac [2] b1 aa [2] ad ad [2] b1 82 }

  condition:
    any of them
}