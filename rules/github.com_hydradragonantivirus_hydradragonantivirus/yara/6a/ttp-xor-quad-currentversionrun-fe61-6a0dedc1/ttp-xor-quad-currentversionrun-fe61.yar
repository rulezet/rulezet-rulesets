rule TTP_XOR_QUAD_CurrentVersionRun_fe61 {
  strings:
    $key_fe61 = { ad 0e [2] 89 00 [2] a2 2c [2] 8c 0e [2] 98 15 [2] 97 0f [2] 89 12 [2] 8b 13 [2] 90 15 [2] 8c 12 [2] 90 3d }

  condition:
    any of them
}