rule TTP_XOR_QUAD_CurrentVersionRun_fe53 {
  strings:
    $key_fe53 = { ad 3c [2] 89 32 [2] a2 1e [2] 8c 3c [2] 98 27 [2] 97 3d [2] 89 20 [2] 8b 21 [2] 90 27 [2] 8c 20 [2] 90 0f }

  condition:
    any of them
}