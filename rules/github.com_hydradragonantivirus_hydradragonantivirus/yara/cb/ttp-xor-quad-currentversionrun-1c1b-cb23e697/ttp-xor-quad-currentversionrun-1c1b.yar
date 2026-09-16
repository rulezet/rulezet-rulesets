rule TTP_XOR_QUAD_CurrentVersionRun_1c1b {
  strings:
    $key_1c1b = { 4f 74 [2] 6b 7a [2] 40 56 [2] 6e 74 [2] 7a 6f [2] 75 75 [2] 6b 68 [2] 69 69 [2] 72 6f [2] 6e 68 [2] 72 47 }

  condition:
    any of them
}