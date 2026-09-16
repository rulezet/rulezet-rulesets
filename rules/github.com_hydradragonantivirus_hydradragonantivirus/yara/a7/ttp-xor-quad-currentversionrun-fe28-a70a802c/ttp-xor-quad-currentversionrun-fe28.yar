rule TTP_XOR_QUAD_CurrentVersionRun_fe28 {
  strings:
    $key_fe28 = { ad 47 [2] 89 49 [2] a2 65 [2] 8c 47 [2] 98 5c [2] 97 46 [2] 89 5b [2] 8b 5a [2] 90 5c [2] 8c 5b [2] 90 74 }

  condition:
    any of them
}