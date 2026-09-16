rule TTP_XOR_QUAD_CurrentVersionRun_fe79 {
  strings:
    $key_fe79 = { ad 16 [2] 89 18 [2] a2 34 [2] 8c 16 [2] 98 0d [2] 97 17 [2] 89 0a [2] 8b 0b [2] 90 0d [2] 8c 0a [2] 90 25 }

  condition:
    any of them
}