rule TTP_XOR_QUAD_CurrentVersionRun_3e9f {
  strings:
    $key_3e9f = { 6d f0 [2] 49 fe [2] 62 d2 [2] 4c f0 [2] 58 eb [2] 57 f1 [2] 49 ec [2] 4b ed [2] 50 eb [2] 4c ec [2] 50 c3 }

  condition:
    any of them
}