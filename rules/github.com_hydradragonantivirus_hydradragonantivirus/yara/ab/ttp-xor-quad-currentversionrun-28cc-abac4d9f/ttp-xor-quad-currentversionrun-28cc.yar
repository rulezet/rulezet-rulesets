rule TTP_XOR_QUAD_CurrentVersionRun_28cc {
  strings:
    $key_28cc = { 7b a3 [2] 5f ad [2] 74 81 [2] 5a a3 [2] 4e b8 [2] 41 a2 [2] 5f bf [2] 5d be [2] 46 b8 [2] 5a bf [2] 46 90 }

  condition:
    any of them
}