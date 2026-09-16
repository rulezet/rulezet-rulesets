rule TTP_XOR_QUAD_CurrentVersionRun_3c07 {
  strings:
    $key_3c07 = { 6f 68 [2] 4b 66 [2] 60 4a [2] 4e 68 [2] 5a 73 [2] 55 69 [2] 4b 74 [2] 49 75 [2] 52 73 [2] 4e 74 [2] 52 5b }

  condition:
    any of them
}