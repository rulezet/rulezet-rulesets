rule TTP_XOR_QUAD_CurrentVersionRun_20c6 {
  strings:
    $key_20c6 = { 73 a9 [2] 57 a7 [2] 7c 8b [2] 52 a9 [2] 46 b2 [2] 49 a8 [2] 57 b5 [2] 55 b4 [2] 4e b2 [2] 52 b5 [2] 4e 9a }

  condition:
    any of them
}