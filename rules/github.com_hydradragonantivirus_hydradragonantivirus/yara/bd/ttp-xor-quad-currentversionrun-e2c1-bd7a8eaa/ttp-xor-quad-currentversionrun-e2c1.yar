rule TTP_XOR_QUAD_CurrentVersionRun_e2c1 {
  strings:
    $key_e2c1 = { b1 ae [2] 95 a0 [2] be 8c [2] 90 ae [2] 84 b5 [2] 8b af [2] 95 b2 [2] 97 b3 [2] 8c b5 [2] 90 b2 [2] 8c 9d }

  condition:
    any of them
}