rule TTP_XOR_QUAD_CurrentVersionRun_5253 {
  strings:
    $key_5253 = { 01 3c [2] 25 32 [2] 0e 1e [2] 20 3c [2] 34 27 [2] 3b 3d [2] 25 20 [2] 27 21 [2] 3c 27 [2] 20 20 [2] 3c 0f }

  condition:
    any of them
}