rule TTP_XOR_QUAD_CurrentVersionRun_fe16 {
  strings:
    $key_fe16 = { ad 79 [2] 89 77 [2] a2 5b [2] 8c 79 [2] 98 62 [2] 97 78 [2] 89 65 [2] 8b 64 [2] 90 62 [2] 8c 65 [2] 90 4a }

  condition:
    any of them
}