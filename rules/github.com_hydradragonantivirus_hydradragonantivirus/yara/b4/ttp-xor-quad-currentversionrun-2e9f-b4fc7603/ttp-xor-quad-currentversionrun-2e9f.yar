rule TTP_XOR_QUAD_CurrentVersionRun_2e9f {
  strings:
    $key_2e9f = { 7d f0 [2] 59 fe [2] 72 d2 [2] 5c f0 [2] 48 eb [2] 47 f1 [2] 59 ec [2] 5b ed [2] 40 eb [2] 5c ec [2] 40 c3 }

  condition:
    any of them
}