rule TTP_XOR_QUAD_CurrentVersionRun_eedc {
  strings:
    $key_eedc = { bd b3 [2] 99 bd [2] b2 91 [2] 9c b3 [2] 88 a8 [2] 87 b2 [2] 99 af [2] 9b ae [2] 80 a8 [2] 9c af [2] 80 80 }

  condition:
    any of them
}