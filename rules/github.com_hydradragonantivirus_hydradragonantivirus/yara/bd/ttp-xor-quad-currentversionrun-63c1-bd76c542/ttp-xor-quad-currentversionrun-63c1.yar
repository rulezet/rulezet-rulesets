rule TTP_XOR_QUAD_CurrentVersionRun_63c1 {
  strings:
    $key_63c1 = { 30 ae [2] 14 a0 [2] 3f 8c [2] 11 ae [2] 05 b5 [2] 0a af [2] 14 b2 [2] 16 b3 [2] 0d b5 [2] 11 b2 [2] 0d 9d }

  condition:
    any of them
}