rule TTP_XOR_QUAD_CurrentVersionRun_43cc {
  strings:
    $key_43cc = { 10 a3 [2] 34 ad [2] 1f 81 [2] 31 a3 [2] 25 b8 [2] 2a a2 [2] 34 bf [2] 36 be [2] 2d b8 [2] 31 bf [2] 2d 90 }

  condition:
    any of them
}