rule TTP_XOR_QUAD_CurrentVersionRun_1bde {
  strings:
    $key_1bde = { 48 b1 [2] 6c bf [2] 47 93 [2] 69 b1 [2] 7d aa [2] 72 b0 [2] 6c ad [2] 6e ac [2] 75 aa [2] 69 ad [2] 75 82 }

  condition:
    any of them
}