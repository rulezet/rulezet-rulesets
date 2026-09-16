rule TTP_XOR_QUAD_CurrentVersionRun_3c47 {
  strings:
    $key_3c47 = { 6f 28 [2] 4b 26 [2] 60 0a [2] 4e 28 [2] 5a 33 [2] 55 29 [2] 4b 34 [2] 49 35 [2] 52 33 [2] 4e 34 [2] 52 1b }

  condition:
    any of them
}