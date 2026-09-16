rule TTP_XOR_QUAD_CurrentVersionRun_e1cc {
  strings:
    $key_e1cc = { b2 a3 [2] 96 ad [2] bd 81 [2] 93 a3 [2] 87 b8 [2] 88 a2 [2] 96 bf [2] 94 be [2] 8f b8 [2] 93 bf [2] 8f 90 }

  condition:
    any of them
}