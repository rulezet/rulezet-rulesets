rule TTP_XOR_QUAD_CurrentVersionRun_07b4 {
  strings:
    $key_07b4 = { 54 db [2] 70 d5 [2] 5b f9 [2] 75 db [2] 61 c0 [2] 6e da [2] 70 c7 [2] 72 c6 [2] 69 c0 [2] 75 c7 [2] 69 e8 }

  condition:
    any of them
}