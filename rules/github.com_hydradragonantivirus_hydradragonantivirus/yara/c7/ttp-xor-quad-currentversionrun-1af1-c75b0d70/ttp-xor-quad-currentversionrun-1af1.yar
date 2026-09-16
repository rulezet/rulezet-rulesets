rule TTP_XOR_QUAD_CurrentVersionRun_1af1 {
  strings:
    $key_1af1 = { 49 9e [2] 6d 90 [2] 46 bc [2] 68 9e [2] 7c 85 [2] 73 9f [2] 6d 82 [2] 6f 83 [2] 74 85 [2] 68 82 [2] 74 ad }

  condition:
    any of them
}