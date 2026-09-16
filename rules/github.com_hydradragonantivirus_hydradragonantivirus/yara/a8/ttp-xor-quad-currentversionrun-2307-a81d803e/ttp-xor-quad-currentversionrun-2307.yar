rule TTP_XOR_QUAD_CurrentVersionRun_2307 {
  strings:
    $key_2307 = { 70 68 [2] 54 66 [2] 7f 4a [2] 51 68 [2] 45 73 [2] 4a 69 [2] 54 74 [2] 56 75 [2] 4d 73 [2] 51 74 [2] 4d 5b }

  condition:
    any of them
}