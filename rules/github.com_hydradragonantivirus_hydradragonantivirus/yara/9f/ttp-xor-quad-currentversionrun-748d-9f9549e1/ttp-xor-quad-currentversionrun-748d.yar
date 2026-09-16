rule TTP_XOR_QUAD_CurrentVersionRun_748d {
  strings:
    $key_748d = { 27 e2 [2] 03 ec [2] 28 c0 [2] 06 e2 [2] 12 f9 [2] 1d e3 [2] 03 fe [2] 01 ff [2] 1a f9 [2] 06 fe [2] 1a d1 }

  condition:
    any of them
}