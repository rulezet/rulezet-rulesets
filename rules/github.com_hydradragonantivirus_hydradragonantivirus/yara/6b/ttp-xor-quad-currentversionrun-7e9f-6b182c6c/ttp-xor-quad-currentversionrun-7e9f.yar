rule TTP_XOR_QUAD_CurrentVersionRun_7e9f {
  strings:
    $key_7e9f = { 2d f0 [2] 09 fe [2] 22 d2 [2] 0c f0 [2] 18 eb [2] 17 f1 [2] 09 ec [2] 0b ed [2] 10 eb [2] 0c ec [2] 10 c3 }

  condition:
    any of them
}