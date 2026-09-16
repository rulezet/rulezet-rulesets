rule TTP_XOR_QUAD_CurrentVersionRun_43c1 {
  strings:
    $key_43c1 = { 10 ae [2] 34 a0 [2] 1f 8c [2] 31 ae [2] 25 b5 [2] 2a af [2] 34 b2 [2] 36 b3 [2] 2d b5 [2] 31 b2 [2] 2d 9d }

  condition:
    any of them
}