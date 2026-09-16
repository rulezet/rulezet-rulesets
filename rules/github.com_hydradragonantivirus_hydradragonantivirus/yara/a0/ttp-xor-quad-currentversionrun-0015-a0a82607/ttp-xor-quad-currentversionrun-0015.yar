rule TTP_XOR_QUAD_CurrentVersionRun_0015 {
  strings:
    $key_0015 = { 53 7a [2] 77 74 [2] 5c 58 [2] 72 7a [2] 66 61 [2] 69 7b [2] 77 66 [2] 75 67 [2] 6e 61 [2] 72 66 [2] 6e 49 }

  condition:
    any of them
}