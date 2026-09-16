rule TTP_XOR_QUAD_CurrentVersionRun_ff96 {
  strings:
    $key_ff96 = { ac f9 [2] 88 f7 [2] a3 db [2] 8d f9 [2] 99 e2 [2] 96 f8 [2] 88 e5 [2] 8a e4 [2] 91 e2 [2] 8d e5 [2] 91 ca }

  condition:
    any of them
}