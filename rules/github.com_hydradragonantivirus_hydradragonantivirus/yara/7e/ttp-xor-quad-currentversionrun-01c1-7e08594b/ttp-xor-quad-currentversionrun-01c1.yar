rule TTP_XOR_QUAD_CurrentVersionRun_01c1 {
  strings:
    $key_01c1 = { 52 ae [2] 76 a0 [2] 5d 8c [2] 73 ae [2] 67 b5 [2] 68 af [2] 76 b2 [2] 74 b3 [2] 6f b5 [2] 73 b2 [2] 6f 9d }

  condition:
    any of them
}