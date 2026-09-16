rule TTP_XOR_QUAD_CurrentVersionRun_73c1 {
  strings:
    $key_73c1 = { 20 ae [2] 04 a0 [2] 2f 8c [2] 01 ae [2] 15 b5 [2] 1a af [2] 04 b2 [2] 06 b3 [2] 1d b5 [2] 01 b2 [2] 1d 9d }

  condition:
    any of them
}