rule TTP_XOR_QUAD_CurrentVersionRun_f653 {
  strings:
    $key_f653 = { a5 3c [2] 81 32 [2] aa 1e [2] 84 3c [2] 90 27 [2] 9f 3d [2] 81 20 [2] 83 21 [2] 98 27 [2] 84 20 [2] 98 0f }

  condition:
    any of them
}