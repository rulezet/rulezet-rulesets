rule TTP_XOR_QUAD_CurrentVersionRun_e8f1 {
  strings:
    $key_e8f1 = { bb 9e [2] 9f 90 [2] b4 bc [2] 9a 9e [2] 8e 85 [2] 81 9f [2] 9f 82 [2] 9d 83 [2] 86 85 [2] 9a 82 [2] 86 ad }

  condition:
    any of them
}