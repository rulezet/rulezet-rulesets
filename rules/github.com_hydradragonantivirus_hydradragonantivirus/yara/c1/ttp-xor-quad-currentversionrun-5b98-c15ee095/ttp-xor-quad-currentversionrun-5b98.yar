rule TTP_XOR_QUAD_CurrentVersionRun_5b98 {
  strings:
    $key_5b98 = { 08 f7 [2] 2c f9 [2] 07 d5 [2] 29 f7 [2] 3d ec [2] 32 f6 [2] 2c eb [2] 2e ea [2] 35 ec [2] 29 eb [2] 35 c4 }

  condition:
    any of them
}