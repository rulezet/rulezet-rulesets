rule TTP_XOR_QUAD_CurrentVersionRun_b5bf {
  strings:
    $key_b5bf = { e6 d0 [2] c2 de [2] e9 f2 [2] c7 d0 [2] d3 cb [2] dc d1 [2] c2 cc [2] c0 cd [2] db cb [2] c7 cc [2] db e3 }

  condition:
    any of them
}