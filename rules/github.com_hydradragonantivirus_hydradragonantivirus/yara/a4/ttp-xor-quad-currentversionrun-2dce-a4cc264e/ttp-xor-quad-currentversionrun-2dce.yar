rule TTP_XOR_QUAD_CurrentVersionRun_2dce {
  strings:
    $key_2dce = { 7e a1 [2] 5a af [2] 71 83 [2] 5f a1 [2] 4b ba [2] 44 a0 [2] 5a bd [2] 58 bc [2] 43 ba [2] 5f bd [2] 43 92 }

  condition:
    any of them
}