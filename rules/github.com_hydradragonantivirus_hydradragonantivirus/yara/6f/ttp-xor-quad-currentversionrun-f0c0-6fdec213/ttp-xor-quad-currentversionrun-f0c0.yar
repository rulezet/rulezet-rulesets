rule TTP_XOR_QUAD_CurrentVersionRun_f0c0 {
  strings:
    $key_f0c0 = { a3 af [2] 87 a1 [2] ac 8d [2] 82 af [2] 96 b4 [2] 99 ae [2] 87 b3 [2] 85 b2 [2] 9e b4 [2] 82 b3 [2] 9e 9c }

  condition:
    any of them
}