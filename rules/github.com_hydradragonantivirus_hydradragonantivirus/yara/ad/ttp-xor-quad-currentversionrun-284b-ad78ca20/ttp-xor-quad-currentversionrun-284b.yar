rule TTP_XOR_QUAD_CurrentVersionRun_284b {
  strings:
    $key_284b = { 7b 24 [2] 5f 2a [2] 74 06 [2] 5a 24 [2] 4e 3f [2] 41 25 [2] 5f 38 [2] 5d 39 [2] 46 3f [2] 5a 38 [2] 46 17 }

  condition:
    any of them
}