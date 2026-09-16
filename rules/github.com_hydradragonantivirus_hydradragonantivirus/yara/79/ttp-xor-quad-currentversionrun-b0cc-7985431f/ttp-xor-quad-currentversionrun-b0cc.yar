rule TTP_XOR_QUAD_CurrentVersionRun_b0cc {
  strings:
    $key_b0cc = { e3 a3 [2] c7 ad [2] ec 81 [2] c2 a3 [2] d6 b8 [2] d9 a2 [2] c7 bf [2] c5 be [2] de b8 [2] c2 bf [2] de 90 }

  condition:
    any of them
}