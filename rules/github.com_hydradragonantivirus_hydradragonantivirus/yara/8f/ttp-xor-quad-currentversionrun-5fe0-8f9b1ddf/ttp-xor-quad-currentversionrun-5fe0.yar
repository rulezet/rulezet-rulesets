rule TTP_XOR_QUAD_CurrentVersionRun_5fe0 {
  strings:
    $key_5fe0 = { 0c 8f [2] 28 81 [2] 03 ad [2] 2d 8f [2] 39 94 [2] 36 8e [2] 28 93 [2] 2a 92 [2] 31 94 [2] 2d 93 [2] 31 bc }

  condition:
    any of them
}