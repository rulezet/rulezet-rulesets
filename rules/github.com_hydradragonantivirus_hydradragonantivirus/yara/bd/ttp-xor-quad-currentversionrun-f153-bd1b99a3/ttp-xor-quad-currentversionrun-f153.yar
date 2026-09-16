rule TTP_XOR_QUAD_CurrentVersionRun_f153 {
  strings:
    $key_f153 = { a2 3c [2] 86 32 [2] ad 1e [2] 83 3c [2] 97 27 [2] 98 3d [2] 86 20 [2] 84 21 [2] 9f 27 [2] 83 20 [2] 9f 0f }

  condition:
    any of them
}