rule TTP_XOR_QUAD_CurrentVersionRun_e6a6 {
  strings:
    $key_e6a6 = { b5 c9 [2] 91 c7 [2] ba eb [2] 94 c9 [2] 80 d2 [2] 8f c8 [2] 91 d5 [2] 93 d4 [2] 88 d2 [2] 94 d5 [2] 88 fa }

  condition:
    any of them
}