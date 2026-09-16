rule TTP_XOR_QUAD_CurrentVersionRun_4953 {
  strings:
    $key_4953 = { 1a 3c [2] 3e 32 [2] 15 1e [2] 3b 3c [2] 2f 27 [2] 20 3d [2] 3e 20 [2] 3c 21 [2] 27 27 [2] 3b 20 [2] 27 0f }

  condition:
    any of them
}