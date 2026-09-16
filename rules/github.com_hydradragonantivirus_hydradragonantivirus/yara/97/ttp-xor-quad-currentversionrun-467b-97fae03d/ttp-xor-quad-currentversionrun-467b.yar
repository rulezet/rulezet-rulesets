rule TTP_XOR_QUAD_CurrentVersionRun_467b {
  strings:
    $key_467b = { 15 14 [2] 31 1a [2] 1a 36 [2] 34 14 [2] 20 0f [2] 2f 15 [2] 31 08 [2] 33 09 [2] 28 0f [2] 34 08 [2] 28 27 }

  condition:
    any of them
}