rule TTP_XOR_QUAD_CurrentVersionRun_49cc {
  strings:
    $key_49cc = { 1a a3 [2] 3e ad [2] 15 81 [2] 3b a3 [2] 2f b8 [2] 20 a2 [2] 3e bf [2] 3c be [2] 27 b8 [2] 3b bf [2] 27 90 }

  condition:
    any of them
}