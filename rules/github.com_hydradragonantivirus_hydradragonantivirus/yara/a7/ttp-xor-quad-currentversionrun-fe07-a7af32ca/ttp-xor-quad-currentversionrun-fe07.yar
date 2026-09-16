rule TTP_XOR_QUAD_CurrentVersionRun_fe07 {
  strings:
    $key_fe07 = { ad 68 [2] 89 66 [2] a2 4a [2] 8c 68 [2] 98 73 [2] 97 69 [2] 89 74 [2] 8b 75 [2] 90 73 [2] 8c 74 [2] 90 5b }

  condition:
    any of them
}