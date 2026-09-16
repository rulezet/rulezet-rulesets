rule TTP_XOR_QUAD_CurrentVersionRun_0ff1 {
  strings:
    $key_0ff1 = { 5c 9e [2] 78 90 [2] 53 bc [2] 7d 9e [2] 69 85 [2] 66 9f [2] 78 82 [2] 7a 83 [2] 61 85 [2] 7d 82 [2] 61 ad }

  condition:
    any of them
}