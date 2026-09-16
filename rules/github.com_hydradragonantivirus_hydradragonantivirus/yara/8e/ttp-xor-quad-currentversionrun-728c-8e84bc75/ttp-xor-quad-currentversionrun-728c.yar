rule TTP_XOR_QUAD_CurrentVersionRun_728c {
  strings:
    $key_728c = { 21 e3 [2] 05 ed [2] 2e c1 [2] 00 e3 [2] 14 f8 [2] 1b e2 [2] 05 ff [2] 07 fe [2] 1c f8 [2] 00 ff [2] 1c d0 }

  condition:
    any of them
}