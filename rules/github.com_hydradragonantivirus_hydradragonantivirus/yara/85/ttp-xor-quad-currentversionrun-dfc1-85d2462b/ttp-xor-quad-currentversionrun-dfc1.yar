rule TTP_XOR_QUAD_CurrentVersionRun_dfc1 {
  strings:
    $key_dfc1 = { 8c ae [2] a8 a0 [2] 83 8c [2] ad ae [2] b9 b5 [2] b6 af [2] a8 b2 [2] aa b3 [2] b1 b5 [2] ad b2 [2] b1 9d }

  condition:
    any of them
}