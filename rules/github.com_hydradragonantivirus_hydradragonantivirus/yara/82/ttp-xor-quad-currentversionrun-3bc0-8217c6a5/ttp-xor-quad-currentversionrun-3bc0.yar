rule TTP_XOR_QUAD_CurrentVersionRun_3bc0 {
  strings:
    $key_3bc0 = { 68 af [2] 4c a1 [2] 67 8d [2] 49 af [2] 5d b4 [2] 52 ae [2] 4c b3 [2] 4e b2 [2] 55 b4 [2] 49 b3 [2] 55 9c }

  condition:
    any of them
}