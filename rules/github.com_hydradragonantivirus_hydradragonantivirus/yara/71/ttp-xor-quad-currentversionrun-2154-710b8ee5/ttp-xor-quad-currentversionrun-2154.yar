rule TTP_XOR_QUAD_CurrentVersionRun_2154 {
  strings:
    $key_2154 = { 72 3b [2] 56 35 [2] 7d 19 [2] 53 3b [2] 47 20 [2] 48 3a [2] 56 27 [2] 54 26 [2] 4f 20 [2] 53 27 [2] 4f 08 }

  condition:
    any of them
}