rule TTP_XOR_QUAD_CurrentVersionRun_fe45 {
  strings:
    $key_fe45 = { ad 2a [2] 89 24 [2] a2 08 [2] 8c 2a [2] 98 31 [2] 97 2b [2] 89 36 [2] 8b 37 [2] 90 31 [2] 8c 36 [2] 90 19 }

  condition:
    any of them
}