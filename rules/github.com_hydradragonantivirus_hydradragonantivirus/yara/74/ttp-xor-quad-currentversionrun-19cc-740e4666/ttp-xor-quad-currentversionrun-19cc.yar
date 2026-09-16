rule TTP_XOR_QUAD_CurrentVersionRun_19cc {
  strings:
    $key_19cc = { 4a a3 [2] 6e ad [2] 45 81 [2] 6b a3 [2] 7f b8 [2] 70 a2 [2] 6e bf [2] 6c be [2] 77 b8 [2] 6b bf [2] 77 90 }

  condition:
    any of them
}