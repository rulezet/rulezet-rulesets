rule TTP_XOR_QUAD_CurrentVersionRun_d9ce {
  strings:
    $key_d9ce = { 8a a1 [2] ae af [2] 85 83 [2] ab a1 [2] bf ba [2] b0 a0 [2] ae bd [2] ac bc [2] b7 ba [2] ab bd [2] b7 92 }

  condition:
    any of them
}