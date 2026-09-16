rule TTP_XOR_QUAD_CurrentVersionRun_6d53 {
  strings:
    $key_6d53 = { 3e 3c [2] 1a 32 [2] 31 1e [2] 1f 3c [2] 0b 27 [2] 04 3d [2] 1a 20 [2] 18 21 [2] 03 27 [2] 1f 20 [2] 03 0f }

  condition:
    any of them
}