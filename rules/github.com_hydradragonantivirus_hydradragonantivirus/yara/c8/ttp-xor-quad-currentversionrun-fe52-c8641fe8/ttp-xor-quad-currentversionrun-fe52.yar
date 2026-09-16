rule TTP_XOR_QUAD_CurrentVersionRun_fe52 {
  strings:
    $key_fe52 = { ad 3d [2] 89 33 [2] a2 1f [2] 8c 3d [2] 98 26 [2] 97 3c [2] 89 21 [2] 8b 20 [2] 90 26 [2] 8c 21 [2] 90 0e }

  condition:
    any of them
}