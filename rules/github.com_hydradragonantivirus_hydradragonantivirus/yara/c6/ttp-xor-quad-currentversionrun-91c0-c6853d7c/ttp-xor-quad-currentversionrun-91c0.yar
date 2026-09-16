rule TTP_XOR_QUAD_CurrentVersionRun_91c0 {
  strings:
    $key_91c0 = { c2 af [2] e6 a1 [2] cd 8d [2] e3 af [2] f7 b4 [2] f8 ae [2] e6 b3 [2] e4 b2 [2] ff b4 [2] e3 b3 [2] ff 9c }

  condition:
    any of them
}