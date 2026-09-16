rule TTP_XOR_QUAD_CurrentVersionRun_ded2 {
  strings:
    $key_ded2 = { 8d bd [2] a9 b3 [2] 82 9f [2] ac bd [2] b8 a6 [2] b7 bc [2] a9 a1 [2] ab a0 [2] b0 a6 [2] ac a1 [2] b0 8e }

  condition:
    any of them
}