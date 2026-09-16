rule TTP_XOR_QUAD_CurrentVersionRun_e98c {
  strings:
    $key_e98c = { ba e3 [2] 9e ed [2] b5 c1 [2] 9b e3 [2] 8f f8 [2] 80 e2 [2] 9e ff [2] 9c fe [2] 87 f8 [2] 9b ff [2] 87 d0 }

  condition:
    any of them
}