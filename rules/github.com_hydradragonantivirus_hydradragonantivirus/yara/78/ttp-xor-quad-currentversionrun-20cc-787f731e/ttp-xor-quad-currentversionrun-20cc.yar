rule TTP_XOR_QUAD_CurrentVersionRun_20cc {
  strings:
    $key_20cc = { 73 a3 [2] 57 ad [2] 7c 81 [2] 52 a3 [2] 46 b8 [2] 49 a2 [2] 57 bf [2] 55 be [2] 4e b8 [2] 52 bf [2] 4e 90 }

  condition:
    any of them
}