rule TTP_XOR_QUAD_CurrentVersionRun_50c1 {
  strings:
    $key_50c1 = { 03 ae [2] 27 a0 [2] 0c 8c [2] 22 ae [2] 36 b5 [2] 39 af [2] 27 b2 [2] 25 b3 [2] 3e b5 [2] 22 b2 [2] 3e 9d }

  condition:
    any of them
}