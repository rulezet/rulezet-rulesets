rule TTP_XOR_QUAD_CurrentVersionRun_0596 {
  strings:
    $key_0596 = { 56 f9 [2] 72 f7 [2] 59 db [2] 77 f9 [2] 63 e2 [2] 6c f8 [2] 72 e5 [2] 70 e4 [2] 6b e2 [2] 77 e5 [2] 6b ca }

  condition:
    any of them
}