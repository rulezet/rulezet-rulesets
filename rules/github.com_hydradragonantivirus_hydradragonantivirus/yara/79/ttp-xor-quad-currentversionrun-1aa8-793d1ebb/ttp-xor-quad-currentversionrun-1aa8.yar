rule TTP_XOR_QUAD_CurrentVersionRun_1aa8 {
  strings:
    $key_1aa8 = { 49 c7 [2] 6d c9 [2] 46 e5 [2] 68 c7 [2] 7c dc [2] 73 c6 [2] 6d db [2] 6f da [2] 74 dc [2] 68 db [2] 74 f4 }

  condition:
    any of them
}