rule TTP_XOR_QUAD_CurrentVersionRun_4753 {
  strings:
    $key_4753 = { 14 3c [2] 30 32 [2] 1b 1e [2] 35 3c [2] 21 27 [2] 2e 3d [2] 30 20 [2] 32 21 [2] 29 27 [2] 35 20 [2] 29 0f }

  condition:
    any of them
}