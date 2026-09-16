rule TTP_XOR_QUAD_CurrentVersionRun_7c8c {
  strings:
    $key_7c8c = { 2f e3 [2] 0b ed [2] 20 c1 [2] 0e e3 [2] 1a f8 [2] 15 e2 [2] 0b ff [2] 09 fe [2] 12 f8 [2] 0e ff [2] 12 d0 }

  condition:
    any of them
}