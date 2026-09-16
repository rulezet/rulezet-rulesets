rule TTP_XOR_QUAD_CurrentVersionRun_6bc1 {
  strings:
    $key_6bc1 = { 38 ae [2] 1c a0 [2] 37 8c [2] 19 ae [2] 0d b5 [2] 02 af [2] 1c b2 [2] 1e b3 [2] 05 b5 [2] 19 b2 [2] 05 9d }

  condition:
    any of them
}