rule TTP_XOR_QUAD_CurrentVersionRun_ed98 {
  strings:
    $key_ed98 = { be f7 [2] 9a f9 [2] b1 d5 [2] 9f f7 [2] 8b ec [2] 84 f6 [2] 9a eb [2] 98 ea [2] 83 ec [2] 9f eb [2] 83 c4 }

  condition:
    any of them
}