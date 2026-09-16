rule TTP_XOR_QUAD_CurrentVersionRun_13e0 {
  strings:
    $key_13e0 = { 40 8f [2] 64 81 [2] 4f ad [2] 61 8f [2] 75 94 [2] 7a 8e [2] 64 93 [2] 66 92 [2] 7d 94 [2] 61 93 [2] 7d bc }

  condition:
    any of them
}