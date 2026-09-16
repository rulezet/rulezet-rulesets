rule TTP_XOR_QUAD_CurrentVersionRun_72c1 {
  strings:
    $key_72c1 = { 21 ae [2] 05 a0 [2] 2e 8c [2] 00 ae [2] 14 b5 [2] 1b af [2] 05 b2 [2] 07 b3 [2] 1c b5 [2] 00 b2 [2] 1c 9d }

  condition:
    any of them
}