rule TTP_XOR_QUAD_CurrentVersionRun_f7c0 {
  strings:
    $key_f7c0 = { a4 af [2] 80 a1 [2] ab 8d [2] 85 af [2] 91 b4 [2] 9e ae [2] 80 b3 [2] 82 b2 [2] 99 b4 [2] 85 b3 [2] 99 9c }

  condition:
    any of them
}