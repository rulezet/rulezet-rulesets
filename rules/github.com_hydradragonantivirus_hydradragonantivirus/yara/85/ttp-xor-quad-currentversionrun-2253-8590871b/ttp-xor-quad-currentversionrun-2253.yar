rule TTP_XOR_QUAD_CurrentVersionRun_2253 {
  strings:
    $key_2253 = { 71 3c [2] 55 32 [2] 7e 1e [2] 50 3c [2] 44 27 [2] 4b 3d [2] 55 20 [2] 57 21 [2] 4c 27 [2] 50 20 [2] 4c 0f }

  condition:
    any of them
}