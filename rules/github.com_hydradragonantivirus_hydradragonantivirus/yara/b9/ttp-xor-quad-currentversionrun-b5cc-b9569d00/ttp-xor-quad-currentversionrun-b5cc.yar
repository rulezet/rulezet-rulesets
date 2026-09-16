rule TTP_XOR_QUAD_CurrentVersionRun_b5cc {
  strings:
    $key_b5cc = { e6 a3 [2] c2 ad [2] e9 81 [2] c7 a3 [2] d3 b8 [2] dc a2 [2] c2 bf [2] c0 be [2] db b8 [2] c7 bf [2] db 90 }

  condition:
    any of them
}