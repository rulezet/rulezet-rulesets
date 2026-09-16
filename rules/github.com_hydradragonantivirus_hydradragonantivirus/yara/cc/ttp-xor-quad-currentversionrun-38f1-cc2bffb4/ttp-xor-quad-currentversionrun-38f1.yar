rule TTP_XOR_QUAD_CurrentVersionRun_38f1 {
  strings:
    $key_38f1 = { 6b 9e [2] 4f 90 [2] 64 bc [2] 4a 9e [2] 5e 85 [2] 51 9f [2] 4f 82 [2] 4d 83 [2] 56 85 [2] 4a 82 [2] 56 ad }

  condition:
    any of them
}