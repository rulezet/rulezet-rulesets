rule TTP_XOR_QUAD_CurrentVersionRun_fe69 {
  strings:
    $key_fe69 = { ad 06 [2] 89 08 [2] a2 24 [2] 8c 06 [2] 98 1d [2] 97 07 [2] 89 1a [2] 8b 1b [2] 90 1d [2] 8c 1a [2] 90 35 }

  condition:
    any of them
}