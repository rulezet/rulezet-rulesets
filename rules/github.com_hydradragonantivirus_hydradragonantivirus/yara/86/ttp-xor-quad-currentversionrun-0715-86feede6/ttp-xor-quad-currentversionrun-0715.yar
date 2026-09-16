rule TTP_XOR_QUAD_CurrentVersionRun_0715 {
  strings:
    $key_0715 = { 54 7a [2] 70 74 [2] 5b 58 [2] 75 7a [2] 61 61 [2] 6e 7b [2] 70 66 [2] 72 67 [2] 69 61 [2] 75 66 [2] 69 49 }

  condition:
    any of them
}