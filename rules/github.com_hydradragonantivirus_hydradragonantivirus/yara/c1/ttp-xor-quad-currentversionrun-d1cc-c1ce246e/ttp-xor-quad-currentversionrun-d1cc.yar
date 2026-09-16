rule TTP_XOR_QUAD_CurrentVersionRun_d1cc {
  strings:
    $key_d1cc = { 82 a3 [2] a6 ad [2] 8d 81 [2] a3 a3 [2] b7 b8 [2] b8 a2 [2] a6 bf [2] a4 be [2] bf b8 [2] a3 bf [2] bf 90 }

  condition:
    any of them
}