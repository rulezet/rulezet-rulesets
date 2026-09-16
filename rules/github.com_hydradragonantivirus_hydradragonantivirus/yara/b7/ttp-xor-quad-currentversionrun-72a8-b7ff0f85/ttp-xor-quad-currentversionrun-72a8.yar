rule TTP_XOR_QUAD_CurrentVersionRun_72a8 {
  strings:
    $key_72a8 = { 21 c7 [2] 05 c9 [2] 2e e5 [2] 00 c7 [2] 14 dc [2] 1b c6 [2] 05 db [2] 07 da [2] 1c dc [2] 00 db [2] 1c f4 }

  condition:
    any of them
}