rule TTP_XOR_QUAD_CurrentVersionRun_5d53 {
  strings:
    $key_5d53 = { 0e 3c [2] 2a 32 [2] 01 1e [2] 2f 3c [2] 3b 27 [2] 34 3d [2] 2a 20 [2] 28 21 [2] 33 27 [2] 2f 20 [2] 33 0f }

  condition:
    any of them
}