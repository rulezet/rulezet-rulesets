rule TTP_XOR_QUAD_CurrentVersionRun_becc {
  strings:
    $key_becc = { ed a3 [2] c9 ad [2] e2 81 [2] cc a3 [2] d8 b8 [2] d7 a2 [2] c9 bf [2] cb be [2] d0 b8 [2] cc bf [2] d0 90 }

  condition:
    any of them
}