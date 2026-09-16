rule TTP_XOR_QUAD_CurrentVersionRun_5c8c {
  strings:
    $key_5c8c = { 0f e3 [2] 2b ed [2] 00 c1 [2] 2e e3 [2] 3a f8 [2] 35 e2 [2] 2b ff [2] 29 fe [2] 32 f8 [2] 2e ff [2] 32 d0 }

  condition:
    any of them
}