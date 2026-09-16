rule TTP_XOR_QUAD_CurrentVersionRun_57cc {
  strings:
    $key_57cc = { 04 a3 [2] 20 ad [2] 0b 81 [2] 25 a3 [2] 31 b8 [2] 3e a2 [2] 20 bf [2] 22 be [2] 39 b8 [2] 25 bf [2] 39 90 }

  condition:
    any of them
}