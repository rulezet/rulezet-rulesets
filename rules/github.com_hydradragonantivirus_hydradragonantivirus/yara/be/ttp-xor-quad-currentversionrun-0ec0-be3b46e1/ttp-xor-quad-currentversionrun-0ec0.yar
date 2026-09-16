rule TTP_XOR_QUAD_CurrentVersionRun_0ec0 {
  strings:
    $key_0ec0 = { 5d af [2] 79 a1 [2] 52 8d [2] 7c af [2] 68 b4 [2] 67 ae [2] 79 b3 [2] 7b b2 [2] 60 b4 [2] 7c b3 [2] 60 9c }

  condition:
    any of them
}