rule TTP_XOR_QUAD_CurrentVersionRun_7f35 {
  strings:
    $key_7f35 = { 2c 5a [2] 08 54 [2] 23 78 [2] 0d 5a [2] 19 41 [2] 16 5b [2] 08 46 [2] 0a 47 [2] 11 41 [2] 0d 46 [2] 11 69 }

  condition:
    any of them
}