rule TTP_XOR_QUAD_CurrentVersionRun_58cc {
  strings:
    $key_58cc = { 0b a3 [2] 2f ad [2] 04 81 [2] 2a a3 [2] 3e b8 [2] 31 a2 [2] 2f bf [2] 2d be [2] 36 b8 [2] 2a bf [2] 36 90 }

  condition:
    any of them
}