rule TTP_XOR_QUAD_CurrentVersionRun_e3cc {
  strings:
    $key_e3cc = { b0 a3 [2] 94 ad [2] bf 81 [2] 91 a3 [2] 85 b8 [2] 8a a2 [2] 94 bf [2] 96 be [2] 8d b8 [2] 91 bf [2] 8d 90 }

  condition:
    any of them
}