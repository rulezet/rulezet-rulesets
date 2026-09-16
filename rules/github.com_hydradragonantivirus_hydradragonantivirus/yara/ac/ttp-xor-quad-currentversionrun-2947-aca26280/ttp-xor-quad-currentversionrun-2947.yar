rule TTP_XOR_QUAD_CurrentVersionRun_2947 {
  strings:
    $key_2947 = { 7a 28 [2] 5e 26 [2] 75 0a [2] 5b 28 [2] 4f 33 [2] 40 29 [2] 5e 34 [2] 5c 35 [2] 47 33 [2] 5b 34 [2] 47 1b }

  condition:
    any of them
}