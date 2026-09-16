rule TTP_XOR_QUAD_CurrentVersionRun_fe03 {
  strings:
    $key_fe03 = { ad 6c [2] 89 62 [2] a2 4e [2] 8c 6c [2] 98 77 [2] 97 6d [2] 89 70 [2] 8b 71 [2] 90 77 [2] 8c 70 [2] 90 5f }

  condition:
    any of them
}