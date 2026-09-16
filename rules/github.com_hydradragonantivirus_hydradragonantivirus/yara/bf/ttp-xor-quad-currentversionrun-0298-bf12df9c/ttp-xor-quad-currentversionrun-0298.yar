rule TTP_XOR_QUAD_CurrentVersionRun_0298 {
  strings:
    $key_0298 = { 51 f7 [2] 75 f9 [2] 5e d5 [2] 70 f7 [2] 64 ec [2] 6b f6 [2] 75 eb [2] 77 ea [2] 6c ec [2] 70 eb [2] 6c c4 }

  condition:
    any of them
}