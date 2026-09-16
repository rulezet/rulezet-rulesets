rule TTP_XOR_QUAD_CurrentVersionRun_3bde {
  strings:
    $key_3bde = { 68 b1 [2] 4c bf [2] 67 93 [2] 49 b1 [2] 5d aa [2] 52 b0 [2] 4c ad [2] 4e ac [2] 55 aa [2] 49 ad [2] 55 82 }

  condition:
    any of them
}