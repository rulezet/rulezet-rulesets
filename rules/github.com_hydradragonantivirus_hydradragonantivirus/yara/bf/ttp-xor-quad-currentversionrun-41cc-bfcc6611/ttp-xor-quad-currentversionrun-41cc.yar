rule TTP_XOR_QUAD_CurrentVersionRun_41cc {
  strings:
    $key_41cc = { 12 a3 [2] 36 ad [2] 1d 81 [2] 33 a3 [2] 27 b8 [2] 28 a2 [2] 36 bf [2] 34 be [2] 2f b8 [2] 33 bf [2] 2f 90 }

  condition:
    any of them
}