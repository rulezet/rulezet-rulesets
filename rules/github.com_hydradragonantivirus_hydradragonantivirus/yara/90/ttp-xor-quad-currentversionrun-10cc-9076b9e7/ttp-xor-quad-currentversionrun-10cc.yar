rule TTP_XOR_QUAD_CurrentVersionRun_10cc {
  strings:
    $key_10cc = { 43 a3 [2] 67 ad [2] 4c 81 [2] 62 a3 [2] 76 b8 [2] 79 a2 [2] 67 bf [2] 65 be [2] 7e b8 [2] 62 bf [2] 7e 90 }

  condition:
    any of them
}