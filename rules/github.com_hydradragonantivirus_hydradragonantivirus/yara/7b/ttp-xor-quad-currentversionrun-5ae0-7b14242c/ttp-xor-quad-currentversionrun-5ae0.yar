rule TTP_XOR_QUAD_CurrentVersionRun_5ae0 {
  strings:
    $key_5ae0 = { 09 8f [2] 2d 81 [2] 06 ad [2] 28 8f [2] 3c 94 [2] 33 8e [2] 2d 93 [2] 2f 92 [2] 34 94 [2] 28 93 [2] 34 bc }

  condition:
    any of them
}