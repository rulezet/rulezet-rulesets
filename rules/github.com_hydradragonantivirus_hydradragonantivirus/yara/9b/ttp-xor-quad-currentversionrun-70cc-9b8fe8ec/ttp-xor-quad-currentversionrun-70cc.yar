rule TTP_XOR_QUAD_CurrentVersionRun_70cc {
  strings:
    $key_70cc = { 23 a3 [2] 07 ad [2] 2c 81 [2] 02 a3 [2] 16 b8 [2] 19 a2 [2] 07 bf [2] 05 be [2] 1e b8 [2] 02 bf [2] 1e 90 }

  condition:
    any of them
}