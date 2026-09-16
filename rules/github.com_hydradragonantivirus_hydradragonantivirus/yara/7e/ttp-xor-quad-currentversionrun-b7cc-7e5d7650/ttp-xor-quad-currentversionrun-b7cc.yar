rule TTP_XOR_QUAD_CurrentVersionRun_b7cc {
  strings:
    $key_b7cc = { e4 a3 [2] c0 ad [2] eb 81 [2] c5 a3 [2] d1 b8 [2] de a2 [2] c0 bf [2] c2 be [2] d9 b8 [2] c5 bf [2] d9 90 }

  condition:
    any of them
}