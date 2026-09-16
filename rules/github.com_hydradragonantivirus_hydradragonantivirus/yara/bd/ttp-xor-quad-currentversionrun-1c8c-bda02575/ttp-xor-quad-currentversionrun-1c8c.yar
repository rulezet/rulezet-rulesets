rule TTP_XOR_QUAD_CurrentVersionRun_1c8c {
  strings:
    $key_1c8c = { 4f e3 [2] 6b ed [2] 40 c1 [2] 6e e3 [2] 7a f8 [2] 75 e2 [2] 6b ff [2] 69 fe [2] 72 f8 [2] 6e ff [2] 72 d0 }

  condition:
    any of them
}