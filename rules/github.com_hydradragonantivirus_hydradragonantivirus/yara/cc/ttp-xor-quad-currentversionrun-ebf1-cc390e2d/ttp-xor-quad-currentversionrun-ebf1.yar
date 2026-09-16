rule TTP_XOR_QUAD_CurrentVersionRun_ebf1 {
  strings:
    $key_ebf1 = { b8 9e [2] 9c 90 [2] b7 bc [2] 99 9e [2] 8d 85 [2] 82 9f [2] 9c 82 [2] 9e 83 [2] 85 85 [2] 99 82 [2] 85 ad }

  condition:
    any of them
}