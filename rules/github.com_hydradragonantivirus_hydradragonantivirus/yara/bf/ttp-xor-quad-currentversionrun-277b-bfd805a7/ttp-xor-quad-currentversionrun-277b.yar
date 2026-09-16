rule TTP_XOR_QUAD_CurrentVersionRun_277b {
  strings:
    $key_277b = { 74 14 [2] 50 1a [2] 7b 36 [2] 55 14 [2] 41 0f [2] 4e 15 [2] 50 08 [2] 52 09 [2] 49 0f [2] 55 08 [2] 49 27 }

  condition:
    any of them
}