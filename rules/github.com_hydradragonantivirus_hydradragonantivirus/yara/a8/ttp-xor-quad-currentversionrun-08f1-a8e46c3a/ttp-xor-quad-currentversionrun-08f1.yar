rule TTP_XOR_QUAD_CurrentVersionRun_08f1 {
  strings:
    $key_08f1 = { 5b 9e [2] 7f 90 [2] 54 bc [2] 7a 9e [2] 6e 85 [2] 61 9f [2] 7f 82 [2] 7d 83 [2] 66 85 [2] 7a 82 [2] 66 ad }

  condition:
    any of them
}