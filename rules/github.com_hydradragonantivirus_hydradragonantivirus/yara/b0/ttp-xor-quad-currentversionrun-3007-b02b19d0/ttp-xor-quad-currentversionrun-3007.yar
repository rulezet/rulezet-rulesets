rule TTP_XOR_QUAD_CurrentVersionRun_3007 {
  strings:
    $key_3007 = { 63 68 [2] 47 66 [2] 6c 4a [2] 42 68 [2] 56 73 [2] 59 69 [2] 47 74 [2] 45 75 [2] 5e 73 [2] 42 74 [2] 5e 5b }

  condition:
    any of them
}