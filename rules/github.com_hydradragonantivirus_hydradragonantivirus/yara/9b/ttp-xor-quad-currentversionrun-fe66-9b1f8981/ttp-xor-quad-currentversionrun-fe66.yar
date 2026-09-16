rule TTP_XOR_QUAD_CurrentVersionRun_fe66 {
  strings:
    $key_fe66 = { ad 09 [2] 89 07 [2] a2 2b [2] 8c 09 [2] 98 12 [2] 97 08 [2] 89 15 [2] 8b 14 [2] 90 12 [2] 8c 15 [2] 90 3a }

  condition:
    any of them
}