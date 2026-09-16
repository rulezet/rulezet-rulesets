rule TTP_XOR_QUAD_CurrentVersionRun_fe35 {
  strings:
    $key_fe35 = { ad 5a [2] 89 54 [2] a2 78 [2] 8c 5a [2] 98 41 [2] 97 5b [2] 89 46 [2] 8b 47 [2] 90 41 [2] 8c 46 [2] 90 69 }

  condition:
    any of them
}