rule TTP_XOR_QUAD_CurrentVersionRun_1b1b {
  strings:
    $key_1b1b = { 48 74 [2] 6c 7a [2] 47 56 [2] 69 74 [2] 7d 6f [2] 72 75 [2] 6c 68 [2] 6e 69 [2] 75 6f [2] 69 68 [2] 75 47 }

  condition:
    any of them
}