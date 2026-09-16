rule TTP_XOR_QUAD_CurrentVersionRun_3ef1 {
  strings:
    $key_3ef1 = { 6d 9e [2] 49 90 [2] 62 bc [2] 4c 9e [2] 58 85 [2] 57 9f [2] 49 82 [2] 4b 83 [2] 50 85 [2] 4c 82 [2] 50 ad }

  condition:
    any of them
}