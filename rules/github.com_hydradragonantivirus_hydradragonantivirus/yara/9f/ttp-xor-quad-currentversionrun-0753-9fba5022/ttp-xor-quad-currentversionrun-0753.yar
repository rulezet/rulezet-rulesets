rule TTP_XOR_QUAD_CurrentVersionRun_0753 {
  strings:
    $key_0753 = { 54 3c [2] 70 32 [2] 5b 1e [2] 75 3c [2] 61 27 [2] 6e 3d [2] 70 20 [2] 72 21 [2] 69 27 [2] 75 20 [2] 69 0f }

  condition:
    any of them
}