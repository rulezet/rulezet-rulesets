rule TTP_XOR_QUAD_CurrentVersionRun_43f1 {
  strings:
    $key_43f1 = { 10 9e [2] 34 90 [2] 1f bc [2] 31 9e [2] 25 85 [2] 2a 9f [2] 34 82 [2] 36 83 [2] 2d 85 [2] 31 82 [2] 2d ad }

  condition:
    any of them
}