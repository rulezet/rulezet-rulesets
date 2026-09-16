rule TTP_XOR_QUAD_CurrentVersionRun_57b4 {
  strings:
    $key_57b4 = { 04 db [2] 20 d5 [2] 0b f9 [2] 25 db [2] 31 c0 [2] 3e da [2] 20 c7 [2] 22 c6 [2] 39 c0 [2] 25 c7 [2] 39 e8 }

  condition:
    any of them
}