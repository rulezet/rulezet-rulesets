rule TTP_XOR_QUAD_CurrentVersionRun_2156 {
  strings:
    $key_2156 = { 72 39 [2] 56 37 [2] 7d 1b [2] 53 39 [2] 47 22 [2] 48 38 [2] 56 25 [2] 54 24 [2] 4f 22 [2] 53 25 [2] 4f 0a }

  condition:
    any of them
}