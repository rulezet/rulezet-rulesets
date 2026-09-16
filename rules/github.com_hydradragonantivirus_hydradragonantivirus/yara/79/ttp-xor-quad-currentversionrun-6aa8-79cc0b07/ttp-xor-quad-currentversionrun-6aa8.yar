rule TTP_XOR_QUAD_CurrentVersionRun_6aa8 {
  strings:
    $key_6aa8 = { 39 c7 [2] 1d c9 [2] 36 e5 [2] 18 c7 [2] 0c dc [2] 03 c6 [2] 1d db [2] 1f da [2] 04 dc [2] 18 db [2] 04 f4 }

  condition:
    any of them
}