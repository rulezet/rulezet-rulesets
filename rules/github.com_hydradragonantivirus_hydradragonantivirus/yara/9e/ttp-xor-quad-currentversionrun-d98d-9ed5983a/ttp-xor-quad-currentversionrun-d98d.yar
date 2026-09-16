rule TTP_XOR_QUAD_CurrentVersionRun_d98d {
  strings:
    $key_d98d = { 8a e2 [2] ae ec [2] 85 c0 [2] ab e2 [2] bf f9 [2] b0 e3 [2] ae fe [2] ac ff [2] b7 f9 [2] ab fe [2] b7 d1 }

  condition:
    any of them
}