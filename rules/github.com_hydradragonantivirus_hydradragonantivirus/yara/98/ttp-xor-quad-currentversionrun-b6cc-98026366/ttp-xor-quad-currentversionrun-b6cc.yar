rule TTP_XOR_QUAD_CurrentVersionRun_b6cc {
  strings:
    $key_b6cc = { e5 a3 [2] c1 ad [2] ea 81 [2] c4 a3 [2] d0 b8 [2] df a2 [2] c1 bf [2] c3 be [2] d8 b8 [2] c4 bf [2] d8 90 }

  condition:
    any of them
}