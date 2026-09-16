rule TTP_XOR_QUAD_CurrentVersionRun_18cc {
  strings:
    $key_18cc = { 4b a3 [2] 6f ad [2] 44 81 [2] 6a a3 [2] 7e b8 [2] 71 a2 [2] 6f bf [2] 6d be [2] 76 b8 [2] 6a bf [2] 76 90 }

  condition:
    any of them
}