rule TTP_XOR_QUAD_CurrentVersionRun_d9d2 {
  strings:
    $key_d9d2 = { 8a bd [2] ae b3 [2] 85 9f [2] ab bd [2] bf a6 [2] b0 bc [2] ae a1 [2] ac a0 [2] b7 a6 [2] ab a1 [2] b7 8e }

  condition:
    any of them
}