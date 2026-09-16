rule TTP_XOR_QUAD_CurrentVersionRun_2981 {
  strings:
    $key_2981 = { 7a ee [2] 5e e0 [2] 75 cc [2] 5b ee [2] 4f f5 [2] 40 ef [2] 5e f2 [2] 5c f3 [2] 47 f5 [2] 5b f2 [2] 47 dd }

  condition:
    any of them
}