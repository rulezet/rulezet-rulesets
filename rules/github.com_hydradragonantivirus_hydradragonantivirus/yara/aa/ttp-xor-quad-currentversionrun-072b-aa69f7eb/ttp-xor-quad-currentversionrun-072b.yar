rule TTP_XOR_QUAD_CurrentVersionRun_072b {
  strings:
    $key_072b = { 54 44 [2] 70 4a [2] 5b 66 [2] 75 44 [2] 61 5f [2] 6e 45 [2] 70 58 [2] 72 59 [2] 69 5f [2] 75 58 [2] 69 77 }

  condition:
    any of them
}