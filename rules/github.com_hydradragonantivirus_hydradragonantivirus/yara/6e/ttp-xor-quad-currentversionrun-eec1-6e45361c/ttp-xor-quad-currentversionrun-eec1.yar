rule TTP_XOR_QUAD_CurrentVersionRun_eec1 {
  strings:
    $key_eec1 = { bd ae [2] 99 a0 [2] b2 8c [2] 9c ae [2] 88 b5 [2] 87 af [2] 99 b2 [2] 9b b3 [2] 80 b5 [2] 9c b2 [2] 80 9d }

  condition:
    any of them
}