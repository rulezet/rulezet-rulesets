rule TTP_XOR_QUAD_CurrentVersionRun_fbde {
  strings:
    $key_fbde = { a8 b1 [2] 8c bf [2] a7 93 [2] 89 b1 [2] 9d aa [2] 92 b0 [2] 8c ad [2] 8e ac [2] 95 aa [2] 89 ad [2] 95 82 }

  condition:
    any of them
}