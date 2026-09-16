rule TTP_XOR_QUAD_CurrentVersionRun_e9c1 {
  strings:
    $key_e9c1 = { ba ae [2] 9e a0 [2] b5 8c [2] 9b ae [2] 8f b5 [2] 80 af [2] 9e b2 [2] 9c b3 [2] 87 b5 [2] 9b b2 [2] 87 9d }

  condition:
    any of them
}