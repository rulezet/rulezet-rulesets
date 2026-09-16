rule TTP_XOR_QUAD_CurrentVersionRun_287c {
  strings:
    $key_287c = { 7b 13 [2] 5f 1d [2] 74 31 [2] 5a 13 [2] 4e 08 [2] 41 12 [2] 5f 0f [2] 5d 0e [2] 46 08 [2] 5a 0f [2] 46 20 }

  condition:
    any of them
}