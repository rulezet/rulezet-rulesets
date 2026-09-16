rule TTP_XOR_QUAD_CurrentVersionRun_fe44 {
  strings:
    $key_fe44 = { ad 2b [2] 89 25 [2] a2 09 [2] 8c 2b [2] 98 30 [2] 97 2a [2] 89 37 [2] 8b 36 [2] 90 30 [2] 8c 37 [2] 90 18 }

  condition:
    any of them
}