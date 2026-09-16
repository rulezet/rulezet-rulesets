rule TTP_XOR_QUAD_CurrentVersionRun_287a {
  strings:
    $key_287a = { 7b 15 [2] 5f 1b [2] 74 37 [2] 5a 15 [2] 4e 0e [2] 41 14 [2] 5f 09 [2] 5d 08 [2] 46 0e [2] 5a 09 [2] 46 26 }

  condition:
    any of them
}