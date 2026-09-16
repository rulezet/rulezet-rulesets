rule TTP_XOR_QUAD_CurrentVersionRun_284a {
  strings:
    $key_284a = { 7b 25 [2] 5f 2b [2] 74 07 [2] 5a 25 [2] 4e 3e [2] 41 24 [2] 5f 39 [2] 5d 38 [2] 46 3e [2] 5a 39 [2] 46 16 }

  condition:
    any of them
}