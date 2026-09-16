rule TTP_XOR_QUAD_CurrentVersionRun_0299 {
  strings:
    $key_0299 = { 51 f6 [2] 75 f8 [2] 5e d4 [2] 70 f6 [2] 64 ed [2] 6b f7 [2] 75 ea [2] 77 eb [2] 6c ed [2] 70 ea [2] 6c c5 }

  condition:
    any of them
}