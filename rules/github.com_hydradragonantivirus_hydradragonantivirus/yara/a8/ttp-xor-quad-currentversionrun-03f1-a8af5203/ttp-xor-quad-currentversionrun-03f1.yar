rule TTP_XOR_QUAD_CurrentVersionRun_03f1 {
  strings:
    $key_03f1 = { 50 9e [2] 74 90 [2] 5f bc [2] 71 9e [2] 65 85 [2] 6a 9f [2] 74 82 [2] 76 83 [2] 6d 85 [2] 71 82 [2] 6d ad }

  condition:
    any of them
}