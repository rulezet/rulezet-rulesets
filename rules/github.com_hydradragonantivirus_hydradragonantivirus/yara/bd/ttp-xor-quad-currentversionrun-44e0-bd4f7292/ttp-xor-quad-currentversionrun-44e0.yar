rule TTP_XOR_QUAD_CurrentVersionRun_44e0 {
  strings:
    $key_44e0 = { 17 8f [2] 33 81 [2] 18 ad [2] 36 8f [2] 22 94 [2] 2d 8e [2] 33 93 [2] 31 92 [2] 2a 94 [2] 36 93 [2] 2a bc }

  condition:
    any of them
}