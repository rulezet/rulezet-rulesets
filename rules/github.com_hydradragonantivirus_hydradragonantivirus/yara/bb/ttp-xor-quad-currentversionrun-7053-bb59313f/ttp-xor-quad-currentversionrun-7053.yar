rule TTP_XOR_QUAD_CurrentVersionRun_7053 {
  strings:
    $key_7053 = { 23 3c [2] 07 32 [2] 2c 1e [2] 02 3c [2] 16 27 [2] 19 3d [2] 07 20 [2] 05 21 [2] 1e 27 [2] 02 20 [2] 1e 0f }

  condition:
    any of them
}