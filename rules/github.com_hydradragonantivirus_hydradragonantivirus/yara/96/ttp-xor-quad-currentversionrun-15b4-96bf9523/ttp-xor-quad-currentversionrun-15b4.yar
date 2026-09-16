rule TTP_XOR_QUAD_CurrentVersionRun_15b4 {
  strings:
    $key_15b4 = { 46 db [2] 62 d5 [2] 49 f9 [2] 67 db [2] 73 c0 [2] 7c da [2] 62 c7 [2] 60 c6 [2] 7b c0 [2] 67 c7 [2] 7b e8 }

  condition:
    any of them
}