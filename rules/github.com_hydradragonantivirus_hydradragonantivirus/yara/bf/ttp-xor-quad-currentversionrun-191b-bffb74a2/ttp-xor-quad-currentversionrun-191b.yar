rule TTP_XOR_QUAD_CurrentVersionRun_191b {
  strings:
    $key_191b = { 4a 74 [2] 6e 7a [2] 45 56 [2] 6b 74 [2] 7f 6f [2] 70 75 [2] 6e 68 [2] 6c 69 [2] 77 6f [2] 6b 68 [2] 77 47 }

  condition:
    any of them
}