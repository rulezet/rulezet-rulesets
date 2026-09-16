rule TTP_XOR_QUAD_CurrentVersionRun_3565 {
  strings:
    $key_3565 = { 66 0a [2] 42 04 [2] 69 28 [2] 47 0a [2] 53 11 [2] 5c 0b [2] 42 16 [2] 40 17 [2] 5b 11 [2] 47 16 [2] 5b 39 }

  condition:
    any of them
}