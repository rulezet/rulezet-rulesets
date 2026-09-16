rule TTP_XOR_QUAD_CurrentVersionRun_90cc {
  strings:
    $key_90cc = { c3 a3 [2] e7 ad [2] cc 81 [2] e2 a3 [2] f6 b8 [2] f9 a2 [2] e7 bf [2] e5 be [2] fe b8 [2] e2 bf [2] fe 90 }

  condition:
    any of them
}