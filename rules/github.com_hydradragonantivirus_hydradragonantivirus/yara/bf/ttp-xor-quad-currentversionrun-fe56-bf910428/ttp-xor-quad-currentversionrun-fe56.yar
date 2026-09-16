rule TTP_XOR_QUAD_CurrentVersionRun_fe56 {
  strings:
    $key_fe56 = { ad 39 [2] 89 37 [2] a2 1b [2] 8c 39 [2] 98 22 [2] 97 38 [2] 89 25 [2] 8b 24 [2] 90 22 [2] 8c 25 [2] 90 0a }

  condition:
    any of them
}