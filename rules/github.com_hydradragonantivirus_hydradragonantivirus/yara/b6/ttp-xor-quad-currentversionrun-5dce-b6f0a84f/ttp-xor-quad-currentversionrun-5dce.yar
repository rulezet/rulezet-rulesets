rule TTP_XOR_QUAD_CurrentVersionRun_5dce {
  strings:
    $key_5dce = { 0e a1 [2] 2a af [2] 01 83 [2] 2f a1 [2] 3b ba [2] 34 a0 [2] 2a bd [2] 28 bc [2] 33 ba [2] 2f bd [2] 33 92 }

  condition:
    any of them
}