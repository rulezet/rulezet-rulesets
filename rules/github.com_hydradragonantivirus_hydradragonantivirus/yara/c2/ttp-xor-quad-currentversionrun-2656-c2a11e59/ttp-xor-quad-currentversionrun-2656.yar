rule TTP_XOR_QUAD_CurrentVersionRun_2656 {
  strings:
    $key_2656 = { 75 39 [2] 51 37 [2] 7a 1b [2] 54 39 [2] 40 22 [2] 4f 38 [2] 51 25 [2] 53 24 [2] 48 22 [2] 54 25 [2] 48 0a }

  condition:
    any of them
}