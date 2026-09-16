rule TTP_XOR_QUAD_CurrentVersionRun_12c0 {
  strings:
    $key_12c0 = { 41 af [2] 65 a1 [2] 4e 8d [2] 60 af [2] 74 b4 [2] 7b ae [2] 65 b3 [2] 67 b2 [2] 7c b4 [2] 60 b3 [2] 7c 9c }

  condition:
    any of them
}