rule TTP_XOR_QUAD_CurrentVersionRun_478c {
  strings:
    $key_478c = { 14 e3 [2] 30 ed [2] 1b c1 [2] 35 e3 [2] 21 f8 [2] 2e e2 [2] 30 ff [2] 32 fe [2] 29 f8 [2] 35 ff [2] 29 d0 }

  condition:
    any of them
}