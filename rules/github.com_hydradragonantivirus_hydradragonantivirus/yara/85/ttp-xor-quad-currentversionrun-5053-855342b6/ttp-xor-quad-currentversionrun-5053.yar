rule TTP_XOR_QUAD_CurrentVersionRun_5053 {
  strings:
    $key_5053 = { 03 3c [2] 27 32 [2] 0c 1e [2] 22 3c [2] 36 27 [2] 39 3d [2] 27 20 [2] 25 21 [2] 3e 27 [2] 22 20 [2] 3e 0f }

  condition:
    any of them
}