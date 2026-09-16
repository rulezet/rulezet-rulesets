rule TTP_XOR_QUAD_CurrentVersionRun_071b {
  strings:
    $key_071b = { 54 74 [2] 70 7a [2] 5b 56 [2] 75 74 [2] 61 6f [2] 6e 75 [2] 70 68 [2] 72 69 [2] 69 6f [2] 75 68 [2] 69 47 }

  condition:
    any of them
}