rule TTP_XOR_QUAD_CurrentVersionRun_24b4 {
  strings:
    $key_24b4 = { 77 db [2] 53 d5 [2] 78 f9 [2] 56 db [2] 42 c0 [2] 4d da [2] 53 c7 [2] 51 c6 [2] 4a c0 [2] 56 c7 [2] 4a e8 }

  condition:
    any of them
}