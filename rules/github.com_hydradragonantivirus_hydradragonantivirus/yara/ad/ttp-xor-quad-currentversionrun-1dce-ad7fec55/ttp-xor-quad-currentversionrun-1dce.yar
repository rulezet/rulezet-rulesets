rule TTP_XOR_QUAD_CurrentVersionRun_1dce {
  strings:
    $key_1dce = { 4e a1 [2] 6a af [2] 41 83 [2] 6f a1 [2] 7b ba [2] 74 a0 [2] 6a bd [2] 68 bc [2] 73 ba [2] 6f bd [2] 73 92 }

  condition:
    any of them
}