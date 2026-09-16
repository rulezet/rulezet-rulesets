rule TTP_XOR_QUAD_CurrentVersionRun_3ca8 {
  strings:
    $key_3ca8 = { 6f c7 [2] 4b c9 [2] 60 e5 [2] 4e c7 [2] 5a dc [2] 55 c6 [2] 4b db [2] 49 da [2] 52 dc [2] 4e db [2] 52 f4 }

  condition:
    any of them
}