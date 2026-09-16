rule TTP_XOR_QUAD_CurrentVersionRun_13f1 {
  strings:
    $key_13f1 = { 40 9e [2] 64 90 [2] 4f bc [2] 61 9e [2] 75 85 [2] 7a 9f [2] 64 82 [2] 66 83 [2] 7d 85 [2] 61 82 [2] 7d ad }

  condition:
    any of them
}