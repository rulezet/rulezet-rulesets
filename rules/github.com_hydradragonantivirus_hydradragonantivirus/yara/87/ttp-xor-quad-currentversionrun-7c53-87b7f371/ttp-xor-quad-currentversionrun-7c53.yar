rule TTP_XOR_QUAD_CurrentVersionRun_7c53 {
  strings:
    $key_7c53 = { 2f 3c [2] 0b 32 [2] 20 1e [2] 0e 3c [2] 1a 27 [2] 15 3d [2] 0b 20 [2] 09 21 [2] 12 27 [2] 0e 20 [2] 12 0f }

  condition:
    any of them
}