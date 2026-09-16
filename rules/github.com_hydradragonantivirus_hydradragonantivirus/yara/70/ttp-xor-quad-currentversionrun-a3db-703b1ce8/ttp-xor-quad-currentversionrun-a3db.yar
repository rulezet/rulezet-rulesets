rule TTP_XOR_QUAD_CurrentVersionRun_a3db {
  strings:
    $key_a3db = { f0 b4 [2] d4 ba [2] ff 96 [2] d1 b4 [2] c5 af [2] ca b5 [2] d4 a8 [2] d6 a9 [2] cd af [2] d1 a8 [2] cd 87 }

  condition:
    any of them
}