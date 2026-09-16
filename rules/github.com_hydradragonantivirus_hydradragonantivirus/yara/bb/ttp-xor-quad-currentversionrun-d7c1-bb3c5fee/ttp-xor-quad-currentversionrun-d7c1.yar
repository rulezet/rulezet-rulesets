rule TTP_XOR_QUAD_CurrentVersionRun_d7c1 {
  strings:
    $key_d7c1 = { 84 ae [2] a0 a0 [2] 8b 8c [2] a5 ae [2] b1 b5 [2] be af [2] a0 b2 [2] a2 b3 [2] b9 b5 [2] a5 b2 [2] b9 9d }

  condition:
    any of them
}