rule TTP_XOR_QUAD_CurrentVersionRun_0dce {
  strings:
    $key_0dce = { 5e a1 [2] 7a af [2] 51 83 [2] 7f a1 [2] 6b ba [2] 64 a0 [2] 7a bd [2] 78 bc [2] 63 ba [2] 7f bd [2] 63 92 }

  condition:
    any of them
}