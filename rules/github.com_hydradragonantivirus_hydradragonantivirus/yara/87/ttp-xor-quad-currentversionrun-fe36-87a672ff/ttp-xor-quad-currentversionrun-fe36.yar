rule TTP_XOR_QUAD_CurrentVersionRun_fe36 {
  strings:
    $key_fe36 = { ad 59 [2] 89 57 [2] a2 7b [2] 8c 59 [2] 98 42 [2] 97 58 [2] 89 45 [2] 8b 44 [2] 90 42 [2] 8c 45 [2] 90 6a }

  condition:
    any of them
}