rule TTP_XOR_QUAD_CurrentVersionRun_3507 {
  strings:
    $key_3507 = { 66 68 [2] 42 66 [2] 69 4a [2] 47 68 [2] 53 73 [2] 5c 69 [2] 42 74 [2] 40 75 [2] 5b 73 [2] 47 74 [2] 5b 5b }

  condition:
    any of them
}