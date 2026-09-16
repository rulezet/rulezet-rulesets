rule TTP_XOR_QUAD_CurrentVersionRun_20c0 {
  strings:
    $key_20c0 = { 73 af [2] 57 a1 [2] 7c 8d [2] 52 af [2] 46 b4 [2] 49 ae [2] 57 b3 [2] 55 b2 [2] 4e b4 [2] 52 b3 [2] 4e 9c }

  condition:
    any of them
}