rule TTP_XOR_QUAD_CurrentVersionRun_399f {
  strings:
    $key_399f = { 6a f0 [2] 4e fe [2] 65 d2 [2] 4b f0 [2] 5f eb [2] 50 f1 [2] 4e ec [2] 4c ed [2] 57 eb [2] 4b ec [2] 57 c3 }

  condition:
    any of them
}