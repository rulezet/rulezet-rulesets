rule TTP_XOR_QUAD_CurrentVersionRun_32a8 {
  strings:
    $key_32a8 = { 61 c7 [2] 45 c9 [2] 6e e5 [2] 40 c7 [2] 54 dc [2] 5b c6 [2] 45 db [2] 47 da [2] 5c dc [2] 40 db [2] 5c f4 }

  condition:
    any of them
}