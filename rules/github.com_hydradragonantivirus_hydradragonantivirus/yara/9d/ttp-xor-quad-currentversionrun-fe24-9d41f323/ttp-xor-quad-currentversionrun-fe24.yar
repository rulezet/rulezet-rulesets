rule TTP_XOR_QUAD_CurrentVersionRun_fe24 {
  strings:
    $key_fe24 = { ad 4b [2] 89 45 [2] a2 69 [2] 8c 4b [2] 98 50 [2] 97 4a [2] 89 57 [2] 8b 56 [2] 90 50 [2] 8c 57 [2] 90 78 }

  condition:
    any of them
}