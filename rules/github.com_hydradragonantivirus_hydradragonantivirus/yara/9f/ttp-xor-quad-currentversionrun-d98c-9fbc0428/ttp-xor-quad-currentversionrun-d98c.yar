rule TTP_XOR_QUAD_CurrentVersionRun_d98c {
  strings:
    $key_d98c = { 8a e3 [2] ae ed [2] 85 c1 [2] ab e3 [2] bf f8 [2] b0 e2 [2] ae ff [2] ac fe [2] b7 f8 [2] ab ff [2] b7 d0 }

  condition:
    any of them
}