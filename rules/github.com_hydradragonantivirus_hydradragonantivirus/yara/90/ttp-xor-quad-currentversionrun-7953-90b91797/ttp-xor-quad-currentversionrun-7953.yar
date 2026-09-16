rule TTP_XOR_QUAD_CurrentVersionRun_7953 {
  strings:
    $key_7953 = { 2a 3c [2] 0e 32 [2] 25 1e [2] 0b 3c [2] 1f 27 [2] 10 3d [2] 0e 20 [2] 0c 21 [2] 17 27 [2] 0b 20 [2] 17 0f }

  condition:
    any of them
}