rule TTP_XOR_QUAD_CurrentVersionRun_4653 {
  strings:
    $key_4653 = { 15 3c [2] 31 32 [2] 1a 1e [2] 34 3c [2] 20 27 [2] 2f 3d [2] 31 20 [2] 33 21 [2] 28 27 [2] 34 20 [2] 28 0f }

  condition:
    any of them
}