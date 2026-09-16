rule TTP_XOR_QUAD_CurrentVersionRun_0653 {
  strings:
    $key_0653 = { 55 3c [2] 71 32 [2] 5a 1e [2] 74 3c [2] 60 27 [2] 6f 3d [2] 71 20 [2] 73 21 [2] 68 27 [2] 74 20 [2] 68 0f }

  condition:
    any of them
}