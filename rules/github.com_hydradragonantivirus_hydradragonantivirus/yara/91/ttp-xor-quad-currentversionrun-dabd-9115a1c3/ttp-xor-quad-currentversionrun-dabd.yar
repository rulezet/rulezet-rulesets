rule TTP_XOR_QUAD_CurrentVersionRun_dabd {
  strings:
    $key_dabd = { 89 d2 [2] ad dc [2] 86 f0 [2] a8 d2 [2] bc c9 [2] b3 d3 [2] ad ce [2] af cf [2] b4 c9 [2] a8 ce [2] b4 e1 }

  condition:
    any of them
}