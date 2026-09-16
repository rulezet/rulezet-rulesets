rule TTP_XOR_QUAD_CurrentVersionRun_e3c0 {
  strings:
    $key_e3c0 = { b0 af [2] 94 a1 [2] bf 8d [2] 91 af [2] 85 b4 [2] 8a ae [2] 94 b3 [2] 96 b2 [2] 8d b4 [2] 91 b3 [2] 8d 9c }

  condition:
    any of them
}