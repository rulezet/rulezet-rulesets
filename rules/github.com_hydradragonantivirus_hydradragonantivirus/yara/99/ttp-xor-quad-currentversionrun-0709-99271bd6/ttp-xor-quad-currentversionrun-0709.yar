rule TTP_XOR_QUAD_CurrentVersionRun_0709 {
  strings:
    $key_0709 = { 54 66 [2] 70 68 [2] 5b 44 [2] 75 66 [2] 61 7d [2] 6e 67 [2] 70 7a [2] 72 7b [2] 69 7d [2] 75 7a [2] 69 55 }

  condition:
    any of them
}