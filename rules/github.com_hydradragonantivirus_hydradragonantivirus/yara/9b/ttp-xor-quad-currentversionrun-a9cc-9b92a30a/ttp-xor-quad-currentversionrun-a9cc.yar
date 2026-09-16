rule TTP_XOR_QUAD_CurrentVersionRun_a9cc {
  strings:
    $key_a9cc = { fa a3 [2] de ad [2] f5 81 [2] db a3 [2] cf b8 [2] c0 a2 [2] de bf [2] dc be [2] c7 b8 [2] db bf [2] c7 90 }

  condition:
    any of them
}