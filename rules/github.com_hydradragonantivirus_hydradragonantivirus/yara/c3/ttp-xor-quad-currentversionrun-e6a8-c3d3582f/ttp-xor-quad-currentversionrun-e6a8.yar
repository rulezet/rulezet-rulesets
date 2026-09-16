rule TTP_XOR_QUAD_CurrentVersionRun_e6a8 {
  strings:
    $key_e6a8 = { b5 c7 [2] 91 c9 [2] ba e5 [2] 94 c7 [2] 80 dc [2] 8f c6 [2] 91 db [2] 93 da [2] 88 dc [2] 94 db [2] 88 f4 }

  condition:
    any of them
}