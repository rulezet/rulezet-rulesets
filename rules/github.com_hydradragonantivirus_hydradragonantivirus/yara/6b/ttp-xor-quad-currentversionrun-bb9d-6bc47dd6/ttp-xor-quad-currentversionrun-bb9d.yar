rule TTP_XOR_QUAD_CurrentVersionRun_bb9d {
  strings:
    $key_bb9d = { e8 f2 [2] cc fc [2] e7 d0 [2] c9 f2 [2] dd e9 [2] d2 f3 [2] cc ee [2] ce ef [2] d5 e9 [2] c9 ee [2] d5 c1 }

  condition:
    any of them
}