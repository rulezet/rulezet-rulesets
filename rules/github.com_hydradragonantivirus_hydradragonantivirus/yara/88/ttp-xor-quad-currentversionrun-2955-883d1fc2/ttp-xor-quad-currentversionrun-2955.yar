rule TTP_XOR_QUAD_CurrentVersionRun_2955 {
  strings:
    $key_2955 = { 7a 3a [2] 5e 34 [2] 75 18 [2] 5b 3a [2] 4f 21 [2] 40 3b [2] 5e 26 [2] 5c 27 [2] 47 21 [2] 5b 26 [2] 47 09 }

  condition:
    any of them
}