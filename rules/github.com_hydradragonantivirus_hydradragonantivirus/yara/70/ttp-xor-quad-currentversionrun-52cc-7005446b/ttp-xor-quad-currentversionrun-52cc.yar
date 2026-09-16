rule TTP_XOR_QUAD_CurrentVersionRun_52cc {
  strings:
    $key_52cc = { 01 a3 [2] 25 ad [2] 0e 81 [2] 20 a3 [2] 34 b8 [2] 3b a2 [2] 25 bf [2] 27 be [2] 3c b8 [2] 20 bf [2] 3c 90 }

  condition:
    any of them
}