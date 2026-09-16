rule TTP_XOR_QUAD_CurrentVersionRun_1bc0 {
  strings:
    $key_1bc0 = { 48 af [2] 6c a1 [2] 47 8d [2] 69 af [2] 7d b4 [2] 72 ae [2] 6c b3 [2] 6e b2 [2] 75 b4 [2] 69 b3 [2] 75 9c }

  condition:
    any of them
}