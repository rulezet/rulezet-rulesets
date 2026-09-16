rule TTP_XOR_QUAD_CurrentVersionRun_1953 {
  strings:
    $key_1953 = { 4a 3c [2] 6e 32 [2] 45 1e [2] 6b 3c [2] 7f 27 [2] 70 3d [2] 6e 20 [2] 6c 21 [2] 77 27 [2] 6b 20 [2] 77 0f }

  condition:
    any of them
}