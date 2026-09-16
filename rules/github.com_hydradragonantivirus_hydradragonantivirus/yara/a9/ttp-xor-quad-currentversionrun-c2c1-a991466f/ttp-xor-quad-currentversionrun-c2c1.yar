rule TTP_XOR_QUAD_CurrentVersionRun_c2c1 {
  strings:
    $key_c2c1 = { 91 ae [2] b5 a0 [2] 9e 8c [2] b0 ae [2] a4 b5 [2] ab af [2] b5 b2 [2] b7 b3 [2] ac b5 [2] b0 b2 [2] ac 9d }

  condition:
    any of them
}