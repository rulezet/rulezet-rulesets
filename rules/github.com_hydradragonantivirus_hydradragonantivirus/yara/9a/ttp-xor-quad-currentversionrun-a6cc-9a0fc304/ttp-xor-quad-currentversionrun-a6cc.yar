rule TTP_XOR_QUAD_CurrentVersionRun_a6cc {
  strings:
    $key_a6cc = { f5 a3 [2] d1 ad [2] fa 81 [2] d4 a3 [2] c0 b8 [2] cf a2 [2] d1 bf [2] d3 be [2] c8 b8 [2] d4 bf [2] c8 90 }

  condition:
    any of them
}