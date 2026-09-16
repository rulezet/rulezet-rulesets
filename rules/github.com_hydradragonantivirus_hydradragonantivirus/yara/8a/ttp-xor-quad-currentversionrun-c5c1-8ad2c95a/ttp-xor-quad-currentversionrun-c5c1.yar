rule TTP_XOR_QUAD_CurrentVersionRun_c5c1 {
  strings:
    $key_c5c1 = { 96 ae [2] b2 a0 [2] 99 8c [2] b7 ae [2] a3 b5 [2] ac af [2] b2 b2 [2] b0 b3 [2] ab b5 [2] b7 b2 [2] ab 9d }

  condition:
    any of them
}