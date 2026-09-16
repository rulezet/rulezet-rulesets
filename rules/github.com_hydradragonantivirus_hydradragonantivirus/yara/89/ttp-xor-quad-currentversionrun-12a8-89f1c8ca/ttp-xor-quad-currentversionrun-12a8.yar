rule TTP_XOR_QUAD_CurrentVersionRun_12a8 {
  strings:
    $key_12a8 = { 41 c7 [2] 65 c9 [2] 4e e5 [2] 60 c7 [2] 74 dc [2] 7b c6 [2] 65 db [2] 67 da [2] 7c dc [2] 60 db [2] 7c f4 }

  condition:
    any of them
}