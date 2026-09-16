rule TTP_XOR_QUAD_CurrentVersionRun_2d53 {
  strings:
    $key_2d53 = { 7e 3c [2] 5a 32 [2] 71 1e [2] 5f 3c [2] 4b 27 [2] 44 3d [2] 5a 20 [2] 58 21 [2] 43 27 [2] 5f 20 [2] 43 0f }

  condition:
    any of them
}