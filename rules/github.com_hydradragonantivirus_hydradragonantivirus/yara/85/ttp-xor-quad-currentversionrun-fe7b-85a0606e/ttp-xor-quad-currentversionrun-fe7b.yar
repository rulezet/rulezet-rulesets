rule TTP_XOR_QUAD_CurrentVersionRun_fe7b {
  strings:
    $key_fe7b = { ad 14 [2] 89 1a [2] a2 36 [2] 8c 14 [2] 98 0f [2] 97 15 [2] 89 08 [2] 8b 09 [2] 90 0f [2] 8c 08 [2] 90 27 }

  condition:
    any of them
}