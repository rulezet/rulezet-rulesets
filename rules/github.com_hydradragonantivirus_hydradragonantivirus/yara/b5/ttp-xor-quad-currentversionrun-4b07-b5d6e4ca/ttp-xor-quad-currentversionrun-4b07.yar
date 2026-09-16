rule TTP_XOR_QUAD_CurrentVersionRun_4b07 {
  strings:
    $key_4b07 = { 18 68 [2] 3c 66 [2] 17 4a [2] 39 68 [2] 2d 73 [2] 22 69 [2] 3c 74 [2] 3e 75 [2] 25 73 [2] 39 74 [2] 25 5b }

  condition:
    any of them
}