rule TTP_XOR_QUAD_CurrentVersionRun_1653 {
  strings:
    $key_1653 = { 45 3c [2] 61 32 [2] 4a 1e [2] 64 3c [2] 70 27 [2] 7f 3d [2] 61 20 [2] 63 21 [2] 78 27 [2] 64 20 [2] 78 0f }

  condition:
    any of them
}