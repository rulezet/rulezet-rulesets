rule TTP_XOR_QUAD_CurrentVersionRun_7d53 {
  strings:
    $key_7d53 = { 2e 3c [2] 0a 32 [2] 21 1e [2] 0f 3c [2] 1b 27 [2] 14 3d [2] 0a 20 [2] 08 21 [2] 13 27 [2] 0f 20 [2] 13 0f }

  condition:
    any of them
}