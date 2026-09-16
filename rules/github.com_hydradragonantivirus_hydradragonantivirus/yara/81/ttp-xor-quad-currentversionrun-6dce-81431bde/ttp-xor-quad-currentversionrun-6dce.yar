rule TTP_XOR_QUAD_CurrentVersionRun_6dce {
  strings:
    $key_6dce = { 3e a1 [2] 1a af [2] 31 83 [2] 1f a1 [2] 0b ba [2] 04 a0 [2] 1a bd [2] 18 bc [2] 03 ba [2] 1f bd [2] 03 92 }

  condition:
    any of them
}