rule TTP_XOR_QUAD_CurrentVersionRun_2c8c {
  strings:
    $key_2c8c = { 7f e3 [2] 5b ed [2] 70 c1 [2] 5e e3 [2] 4a f8 [2] 45 e2 [2] 5b ff [2] 59 fe [2] 42 f8 [2] 5e ff [2] 42 d0 }

  condition:
    any of them
}