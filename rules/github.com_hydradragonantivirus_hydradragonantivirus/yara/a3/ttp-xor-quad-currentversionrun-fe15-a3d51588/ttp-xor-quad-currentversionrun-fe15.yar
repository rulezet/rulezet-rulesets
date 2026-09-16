rule TTP_XOR_QUAD_CurrentVersionRun_fe15 {
  strings:
    $key_fe15 = { ad 7a [2] 89 74 [2] a2 58 [2] 8c 7a [2] 98 61 [2] 97 7b [2] 89 66 [2] 8b 67 [2] 90 61 [2] 8c 66 [2] 90 49 }

  condition:
    any of them
}