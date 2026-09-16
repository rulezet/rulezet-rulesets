rule TTP_XOR_QUAD_CurrentVersionRun_7dde {
  strings:
    $key_7dde = { 2e b1 [2] 0a bf [2] 21 93 [2] 0f b1 [2] 1b aa [2] 14 b0 [2] 0a ad [2] 08 ac [2] 13 aa [2] 0f ad [2] 13 82 }

  condition:
    any of them
}