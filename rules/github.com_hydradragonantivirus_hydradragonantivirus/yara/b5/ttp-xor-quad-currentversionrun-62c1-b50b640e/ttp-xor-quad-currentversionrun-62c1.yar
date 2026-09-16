rule TTP_XOR_QUAD_CurrentVersionRun_62c1 {
  strings:
    $key_62c1 = { 31 ae [2] 15 a0 [2] 3e 8c [2] 10 ae [2] 04 b5 [2] 0b af [2] 15 b2 [2] 17 b3 [2] 0c b5 [2] 10 b2 [2] 0c 9d }

  condition:
    any of them
}