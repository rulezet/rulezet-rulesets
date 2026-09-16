rule TTP_XOR_QUAD_CurrentVersionRun_1ff1 {
  strings:
    $key_1ff1 = { 4c 9e [2] 68 90 [2] 43 bc [2] 6d 9e [2] 79 85 [2] 76 9f [2] 68 82 [2] 6a 83 [2] 71 85 [2] 6d 82 [2] 71 ad }

  condition:
    any of them
}