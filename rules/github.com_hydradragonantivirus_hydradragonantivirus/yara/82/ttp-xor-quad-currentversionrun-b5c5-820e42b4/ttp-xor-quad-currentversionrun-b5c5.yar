rule TTP_XOR_QUAD_CurrentVersionRun_b5c5 {
  strings:
    $key_b5c5 = { e6 aa [2] c2 a4 [2] e9 88 [2] c7 aa [2] d3 b1 [2] dc ab [2] c2 b6 [2] c0 b7 [2] db b1 [2] c7 b6 [2] db 99 }

  condition:
    any of them
}