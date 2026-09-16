rule TTP_XOR_QUAD_CurrentVersionRun_2f27 {
  strings:
    $key_2f27 = { 7c 48 [2] 58 46 [2] 73 6a [2] 5d 48 [2] 49 53 [2] 46 49 [2] 58 54 [2] 5a 55 [2] 41 53 [2] 5d 54 [2] 41 7b }

  condition:
    any of them
}