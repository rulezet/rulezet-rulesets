rule TTP_XOR_QUAD_CurrentVersionRun_68cc {
  strings:
    $key_68cc = { 3b a3 [2] 1f ad [2] 34 81 [2] 1a a3 [2] 0e b8 [2] 01 a2 [2] 1f bf [2] 1d be [2] 06 b8 [2] 1a bf [2] 06 90 }

  condition:
    any of them
}