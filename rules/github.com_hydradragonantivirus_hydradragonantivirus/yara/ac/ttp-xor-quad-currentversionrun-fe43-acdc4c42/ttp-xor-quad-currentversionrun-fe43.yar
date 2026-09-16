rule TTP_XOR_QUAD_CurrentVersionRun_fe43 {
  strings:
    $key_fe43 = { ad 2c [2] 89 22 [2] a2 0e [2] 8c 2c [2] 98 37 [2] 97 2d [2] 89 30 [2] 8b 31 [2] 90 37 [2] 8c 30 [2] 90 1f }

  condition:
    any of them
}