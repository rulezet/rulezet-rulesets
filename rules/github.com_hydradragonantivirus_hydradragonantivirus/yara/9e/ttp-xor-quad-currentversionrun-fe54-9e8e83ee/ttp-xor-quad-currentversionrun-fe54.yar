rule TTP_XOR_QUAD_CurrentVersionRun_fe54 {
  strings:
    $key_fe54 = { ad 3b [2] 89 35 [2] a2 19 [2] 8c 3b [2] 98 20 [2] 97 3a [2] 89 27 [2] 8b 26 [2] 90 20 [2] 8c 27 [2] 90 08 }

  condition:
    any of them
}