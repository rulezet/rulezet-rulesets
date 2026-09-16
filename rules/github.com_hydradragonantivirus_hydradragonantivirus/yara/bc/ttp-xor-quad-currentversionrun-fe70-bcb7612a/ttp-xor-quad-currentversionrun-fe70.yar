rule TTP_XOR_QUAD_CurrentVersionRun_fe70 {
  strings:
    $key_fe70 = { ad 1f [2] 89 11 [2] a2 3d [2] 8c 1f [2] 98 04 [2] 97 1e [2] 89 03 [2] 8b 02 [2] 90 04 [2] 8c 03 [2] 90 2c }

  condition:
    any of them
}