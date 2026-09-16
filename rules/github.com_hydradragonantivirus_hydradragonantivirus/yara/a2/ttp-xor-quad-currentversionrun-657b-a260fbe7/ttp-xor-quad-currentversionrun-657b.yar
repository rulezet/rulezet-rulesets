rule TTP_XOR_QUAD_CurrentVersionRun_657b {
  strings:
    $key_657b = { 36 14 [2] 12 1a [2] 39 36 [2] 17 14 [2] 03 0f [2] 0c 15 [2] 12 08 [2] 10 09 [2] 0b 0f [2] 17 08 [2] 0b 27 }

  condition:
    any of them
}