rule TTP_XOR_QUAD_CurrentVersionRun_fe37 {
  strings:
    $key_fe37 = { ad 58 [2] 89 56 [2] a2 7a [2] 8c 58 [2] 98 43 [2] 97 59 [2] 89 44 [2] 8b 45 [2] 90 43 [2] 8c 44 [2] 90 6b }

  condition:
    any of them
}