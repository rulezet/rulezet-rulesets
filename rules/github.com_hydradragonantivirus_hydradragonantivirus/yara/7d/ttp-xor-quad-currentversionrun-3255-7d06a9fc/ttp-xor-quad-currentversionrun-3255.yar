rule TTP_XOR_QUAD_CurrentVersionRun_3255 {
  strings:
    $key_3255 = { 61 3a [2] 45 34 [2] 6e 18 [2] 40 3a [2] 54 21 [2] 5b 3b [2] 45 26 [2] 47 27 [2] 5c 21 [2] 40 26 [2] 5c 09 }

  condition:
    any of them
}