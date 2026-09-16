rule TTP_XOR_QUAD_CurrentVersionRun_1b98 {
  strings:
    $key_1b98 = { 48 f7 [2] 6c f9 [2] 47 d5 [2] 69 f7 [2] 7d ec [2] 72 f6 [2] 6c eb [2] 6e ea [2] 75 ec [2] 69 eb [2] 75 c4 }

  condition:
    any of them
}