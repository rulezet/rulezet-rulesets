rule TTP_XOR_QUAD_CurrentVersionRun_794b {
  strings:
    $key_794b = { 2a 24 [2] 0e 2a [2] 25 06 [2] 0b 24 [2] 1f 3f [2] 10 25 [2] 0e 38 [2] 0c 39 [2] 17 3f [2] 0b 38 [2] 17 17 }

  condition:
    any of them
}