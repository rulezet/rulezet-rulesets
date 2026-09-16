rule TTP_XOR_QUAD_CurrentVersionRun_50c0 {
  strings:
    $key_50c0 = { 03 af [2] 27 a1 [2] 0c 8d [2] 22 af [2] 36 b4 [2] 39 ae [2] 27 b3 [2] 25 b2 [2] 3e b4 [2] 22 b3 [2] 3e 9c }

  condition:
    any of them
}