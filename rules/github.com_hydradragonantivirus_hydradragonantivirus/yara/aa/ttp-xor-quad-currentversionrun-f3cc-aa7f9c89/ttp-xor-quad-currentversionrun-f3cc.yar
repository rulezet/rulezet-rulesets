rule TTP_XOR_QUAD_CurrentVersionRun_f3cc {
  strings:
    $key_f3cc = { a0 a3 [2] 84 ad [2] af 81 [2] 81 a3 [2] 95 b8 [2] 9a a2 [2] 84 bf [2] 86 be [2] 9d b8 [2] 81 bf [2] 9d 90 }

  condition:
    any of them
}