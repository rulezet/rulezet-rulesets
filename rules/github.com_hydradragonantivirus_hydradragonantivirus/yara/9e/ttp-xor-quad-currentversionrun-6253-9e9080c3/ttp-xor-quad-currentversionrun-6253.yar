rule TTP_XOR_QUAD_CurrentVersionRun_6253 {
  strings:
    $key_6253 = { 31 3c [2] 15 32 [2] 3e 1e [2] 10 3c [2] 04 27 [2] 0b 3d [2] 15 20 [2] 17 21 [2] 0c 27 [2] 10 20 [2] 0c 0f }

  condition:
    any of them
}