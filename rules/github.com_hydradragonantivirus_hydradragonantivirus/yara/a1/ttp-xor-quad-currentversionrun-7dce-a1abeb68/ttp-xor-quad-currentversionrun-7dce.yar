rule TTP_XOR_QUAD_CurrentVersionRun_7dce {
  strings:
    $key_7dce = { 2e a1 [2] 0a af [2] 21 83 [2] 0f a1 [2] 1b ba [2] 14 a0 [2] 0a bd [2] 08 bc [2] 13 ba [2] 0f bd [2] 13 92 }

  condition:
    any of them
}