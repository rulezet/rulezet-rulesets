rule TTP_XOR_QUAD_CurrentVersionRun_34b4 {
  strings:
    $key_34b4 = { 67 db [2] 43 d5 [2] 68 f9 [2] 46 db [2] 52 c0 [2] 5d da [2] 43 c7 [2] 41 c6 [2] 5a c0 [2] 46 c7 [2] 5a e8 }

  condition:
    any of them
}