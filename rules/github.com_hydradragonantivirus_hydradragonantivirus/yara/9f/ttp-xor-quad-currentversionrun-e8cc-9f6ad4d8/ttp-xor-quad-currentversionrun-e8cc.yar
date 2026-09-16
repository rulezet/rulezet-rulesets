rule TTP_XOR_QUAD_CurrentVersionRun_e8cc {
  strings:
    $key_e8cc = { bb a3 [2] 9f ad [2] b4 81 [2] 9a a3 [2] 8e b8 [2] 81 a2 [2] 9f bf [2] 9d be [2] 86 b8 [2] 9a bf [2] 86 90 }

  condition:
    any of them
}