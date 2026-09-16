rule TTP_XOR_QUAD_CurrentVersionRun_48e0 {
  strings:
    $key_48e0 = { 1b 8f [2] 3f 81 [2] 14 ad [2] 3a 8f [2] 2e 94 [2] 21 8e [2] 3f 93 [2] 3d 92 [2] 26 94 [2] 3a 93 [2] 26 bc }

  condition:
    any of them
}