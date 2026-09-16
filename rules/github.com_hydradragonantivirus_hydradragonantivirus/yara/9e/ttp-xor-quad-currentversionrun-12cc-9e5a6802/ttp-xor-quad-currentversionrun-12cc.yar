rule TTP_XOR_QUAD_CurrentVersionRun_12cc {
  strings:
    $key_12cc = { 41 a3 [2] 65 ad [2] 4e 81 [2] 60 a3 [2] 74 b8 [2] 7b a2 [2] 65 bf [2] 67 be [2] 7c b8 [2] 60 bf [2] 7c 90 }

  condition:
    any of them
}