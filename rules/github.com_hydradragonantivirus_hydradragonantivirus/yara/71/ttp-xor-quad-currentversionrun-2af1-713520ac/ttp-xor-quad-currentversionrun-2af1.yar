rule TTP_XOR_QUAD_CurrentVersionRun_2af1 {
  strings:
    $key_2af1 = { 79 9e [2] 5d 90 [2] 76 bc [2] 58 9e [2] 4c 85 [2] 43 9f [2] 5d 82 [2] 5f 83 [2] 44 85 [2] 58 82 [2] 44 ad }

  condition:
    any of them
}