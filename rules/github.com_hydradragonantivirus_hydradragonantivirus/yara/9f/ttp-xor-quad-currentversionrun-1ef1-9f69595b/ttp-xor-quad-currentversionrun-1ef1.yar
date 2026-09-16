rule TTP_XOR_QUAD_CurrentVersionRun_1ef1 {
  strings:
    $key_1ef1 = { 4d 9e [2] 69 90 [2] 42 bc [2] 6c 9e [2] 78 85 [2] 77 9f [2] 69 82 [2] 6b 83 [2] 70 85 [2] 6c 82 [2] 70 ad }

  condition:
    any of them
}