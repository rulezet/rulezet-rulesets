rule TTP_XOR_QUAD_CurrentVersionRun_aebe {
  strings:
    $key_aebe = { fd d1 [2] d9 df [2] f2 f3 [2] dc d1 [2] c8 ca [2] c7 d0 [2] d9 cd [2] db cc [2] c0 ca [2] dc cd [2] c0 e2 }

  condition:
    any of them
}