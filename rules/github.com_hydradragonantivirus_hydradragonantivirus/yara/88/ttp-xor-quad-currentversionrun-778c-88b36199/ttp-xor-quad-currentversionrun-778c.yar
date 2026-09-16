rule TTP_XOR_QUAD_CurrentVersionRun_778c {
  strings:
    $key_778c = { 24 e3 [2] 00 ed [2] 2b c1 [2] 05 e3 [2] 11 f8 [2] 1e e2 [2] 00 ff [2] 02 fe [2] 19 f8 [2] 05 ff [2] 19 d0 }

  condition:
    any of them
}