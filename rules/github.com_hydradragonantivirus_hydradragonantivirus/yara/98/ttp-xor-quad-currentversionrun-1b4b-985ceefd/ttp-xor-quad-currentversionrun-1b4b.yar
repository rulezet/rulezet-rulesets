rule TTP_XOR_QUAD_CurrentVersionRun_1b4b {
  strings:
    $key_1b4b = { 48 24 [2] 6c 2a [2] 47 06 [2] 69 24 [2] 7d 3f [2] 72 25 [2] 6c 38 [2] 6e 39 [2] 75 3f [2] 69 38 [2] 75 17 }

  condition:
    any of them
}