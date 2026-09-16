rule TTP_XOR_QUAD_CurrentVersionRun_3564 {
  strings:
    $key_3564 = { 66 0b [2] 42 05 [2] 69 29 [2] 47 0b [2] 53 10 [2] 5c 0a [2] 42 17 [2] 40 16 [2] 5b 10 [2] 47 17 [2] 5b 38 }

  condition:
    any of them
}