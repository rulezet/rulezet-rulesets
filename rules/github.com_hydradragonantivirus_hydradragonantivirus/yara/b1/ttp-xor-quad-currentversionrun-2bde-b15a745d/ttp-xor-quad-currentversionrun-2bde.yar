rule TTP_XOR_QUAD_CurrentVersionRun_2bde {
  strings:
    $key_2bde = { 78 b1 [2] 5c bf [2] 77 93 [2] 59 b1 [2] 4d aa [2] 42 b0 [2] 5c ad [2] 5e ac [2] 45 aa [2] 59 ad [2] 45 82 }

  condition:
    any of them
}