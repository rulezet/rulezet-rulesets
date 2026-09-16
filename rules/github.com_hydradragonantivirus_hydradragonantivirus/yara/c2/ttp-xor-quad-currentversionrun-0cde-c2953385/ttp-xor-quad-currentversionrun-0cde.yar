rule TTP_XOR_QUAD_CurrentVersionRun_0cde {
  strings:
    $key_0cde = { 5f b1 [2] 7b bf [2] 50 93 [2] 7e b1 [2] 6a aa [2] 65 b0 [2] 7b ad [2] 79 ac [2] 62 aa [2] 7e ad [2] 62 82 }

  condition:
    any of them
}