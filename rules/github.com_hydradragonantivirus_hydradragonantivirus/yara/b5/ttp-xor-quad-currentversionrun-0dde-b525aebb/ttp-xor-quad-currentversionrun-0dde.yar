rule TTP_XOR_QUAD_CurrentVersionRun_0dde {
  strings:
    $key_0dde = { 5e b1 [2] 7a bf [2] 51 93 [2] 7f b1 [2] 6b aa [2] 64 b0 [2] 7a ad [2] 78 ac [2] 63 aa [2] 7f ad [2] 63 82 }

  condition:
    any of them
}