rule TTP_XOR_QUAD_CurrentVersionRun_40cc {
  strings:
    $key_40cc = { 13 a3 [2] 37 ad [2] 1c 81 [2] 32 a3 [2] 26 b8 [2] 29 a2 [2] 37 bf [2] 35 be [2] 2e b8 [2] 32 bf [2] 2e 90 }

  condition:
    any of them
}