rule TTP_XOR_QUAD_CurrentVersionRun_2cde {
  strings:
    $key_2cde = { 7f b1 [2] 5b bf [2] 70 93 [2] 5e b1 [2] 4a aa [2] 45 b0 [2] 5b ad [2] 59 ac [2] 42 aa [2] 5e ad [2] 42 82 }

  condition:
    any of them
}