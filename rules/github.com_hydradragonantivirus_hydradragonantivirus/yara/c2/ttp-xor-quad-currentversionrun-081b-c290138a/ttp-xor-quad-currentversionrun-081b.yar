rule TTP_XOR_QUAD_CurrentVersionRun_081b {
  strings:
    $key_081b = { 5b 74 [2] 7f 7a [2] 54 56 [2] 7a 74 [2] 6e 6f [2] 61 75 [2] 7f 68 [2] 7d 69 [2] 66 6f [2] 7a 68 [2] 66 47 }

  condition:
    any of them
}