rule TTP_XOR_QUAD_CurrentVersionRun_35ad {
  strings:
    $key_35ad = { 66 c2 [2] 42 cc [2] 69 e0 [2] 47 c2 [2] 53 d9 [2] 5c c3 [2] 42 de [2] 40 df [2] 5b d9 [2] 47 de [2] 5b f1 }

  condition:
    any of them
}