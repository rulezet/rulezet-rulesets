rule TTP_XOR_QUAD_CurrentVersionRun_5753 {
  strings:
    $key_5753 = { 04 3c [2] 20 32 [2] 0b 1e [2] 25 3c [2] 31 27 [2] 3e 3d [2] 20 20 [2] 22 21 [2] 39 27 [2] 25 20 [2] 39 0f }

  condition:
    any of them
}