rule TTP_XOR_QUAD_CurrentVersionRun_0f07 {
  strings:
    $key_0f07 = { 5c 68 [2] 78 66 [2] 53 4a [2] 7d 68 [2] 69 73 [2] 66 69 [2] 78 74 [2] 7a 75 [2] 61 73 [2] 7d 74 [2] 61 5b }

  condition:
    any of them
}