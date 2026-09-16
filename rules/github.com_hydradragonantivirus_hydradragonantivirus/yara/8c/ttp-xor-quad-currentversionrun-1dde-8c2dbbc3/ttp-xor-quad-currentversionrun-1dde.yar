rule TTP_XOR_QUAD_CurrentVersionRun_1dde {
  strings:
    $key_1dde = { 4e b1 [2] 6a bf [2] 41 93 [2] 6f b1 [2] 7b aa [2] 74 b0 [2] 6a ad [2] 68 ac [2] 73 aa [2] 6f ad [2] 73 82 }

  condition:
    any of them
}