rule TTP_XOR_QUAD_CurrentVersionRun_fe46 {
  strings:
    $key_fe46 = { ad 29 [2] 89 27 [2] a2 0b [2] 8c 29 [2] 98 32 [2] 97 28 [2] 89 35 [2] 8b 34 [2] 90 32 [2] 8c 35 [2] 90 1a }

  condition:
    any of them
}