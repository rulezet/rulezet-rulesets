rule TTP_XOR_QUAD_CurrentVersionRun_6c1b {
  strings:
    $key_6c1b = { 3f 74 [2] 1b 7a [2] 30 56 [2] 1e 74 [2] 0a 6f [2] 05 75 [2] 1b 68 [2] 19 69 [2] 02 6f [2] 1e 68 [2] 02 47 }

  condition:
    any of them
}