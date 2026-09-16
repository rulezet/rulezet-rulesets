rule TTP_XOR_QUAD_CurrentVersionRun_7c32 {
  strings:
    $key_7c32 = { 2f 5d [2] 0b 53 [2] 20 7f [2] 0e 5d [2] 1a 46 [2] 15 5c [2] 0b 41 [2] 09 40 [2] 12 46 [2] 0e 41 [2] 12 6e }

  condition:
    any of them
}