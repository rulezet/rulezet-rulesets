rule TTP_XOR_QUAD_CurrentVersionRun_48f1 {
  strings:
    $key_48f1 = { 1b 9e [2] 3f 90 [2] 14 bc [2] 3a 9e [2] 2e 85 [2] 21 9f [2] 3f 82 [2] 3d 83 [2] 26 85 [2] 3a 82 [2] 26 ad }

  condition:
    any of them
}