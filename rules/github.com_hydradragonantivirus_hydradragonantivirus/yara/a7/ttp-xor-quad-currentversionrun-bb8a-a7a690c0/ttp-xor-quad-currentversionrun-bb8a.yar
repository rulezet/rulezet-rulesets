rule TTP_XOR_QUAD_CurrentVersionRun_bb8a {
  strings:
    $key_bb8a = { e8 e5 [2] cc eb [2] e7 c7 [2] c9 e5 [2] dd fe [2] d2 e4 [2] cc f9 [2] ce f8 [2] d5 fe [2] c9 f9 [2] d5 d6 }

  condition:
    any of them
}