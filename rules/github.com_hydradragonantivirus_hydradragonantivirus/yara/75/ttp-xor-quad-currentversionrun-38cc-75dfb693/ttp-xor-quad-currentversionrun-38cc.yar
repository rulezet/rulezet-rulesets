rule TTP_XOR_QUAD_CurrentVersionRun_38cc {
  strings:
    $key_38cc = { 6b a3 [2] 4f ad [2] 64 81 [2] 4a a3 [2] 5e b8 [2] 51 a2 [2] 4f bf [2] 4d be [2] 56 b8 [2] 4a bf [2] 56 90 }

  condition:
    any of them
}