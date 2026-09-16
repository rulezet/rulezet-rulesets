rule TTP_XOR_QUAD_CurrentVersionRun_6c8c {
  strings:
    $key_6c8c = { 3f e3 [2] 1b ed [2] 30 c1 [2] 1e e3 [2] 0a f8 [2] 05 e2 [2] 1b ff [2] 19 fe [2] 02 f8 [2] 1e ff [2] 02 d0 }

  condition:
    any of them
}