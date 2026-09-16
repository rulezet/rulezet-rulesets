rule TTP_XOR_QUAD_CurrentVersionRun_05cc {
  strings:
    $key_05cc = { 56 a3 [2] 72 ad [2] 59 81 [2] 77 a3 [2] 63 b8 [2] 6c a2 [2] 72 bf [2] 70 be [2] 6b b8 [2] 77 bf [2] 6b 90 }

  condition:
    any of them
}