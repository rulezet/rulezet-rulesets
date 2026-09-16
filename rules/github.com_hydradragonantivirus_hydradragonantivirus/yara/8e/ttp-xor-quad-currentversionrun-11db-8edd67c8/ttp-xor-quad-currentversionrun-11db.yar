rule TTP_XOR_QUAD_CurrentVersionRun_11db {
  strings:
    $key_11db = { 42 b4 [2] 66 ba [2] 4d 96 [2] 63 b4 [2] 77 af [2] 78 b5 [2] 66 a8 [2] 64 a9 [2] 7f af [2] 63 a8 [2] 7f 87 }

  condition:
    any of them
}