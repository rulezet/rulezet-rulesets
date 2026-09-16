rule TTP_XOR_QUAD_CurrentVersionRun_51cc {
  strings:
    $key_51cc = { 02 a3 [2] 26 ad [2] 0d 81 [2] 23 a3 [2] 37 b8 [2] 38 a2 [2] 26 bf [2] 24 be [2] 3f b8 [2] 23 bf [2] 3f 90 }

  condition:
    any of them
}