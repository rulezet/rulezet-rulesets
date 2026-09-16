rule TTP_XOR_QUAD_CurrentVersionRun_eec0 {
  strings:
    $key_eec0 = { bd af [2] 99 a1 [2] b2 8d [2] 9c af [2] 88 b4 [2] 87 ae [2] 99 b3 [2] 9b b2 [2] 80 b4 [2] 9c b3 [2] 80 9c }

  condition:
    any of them
}