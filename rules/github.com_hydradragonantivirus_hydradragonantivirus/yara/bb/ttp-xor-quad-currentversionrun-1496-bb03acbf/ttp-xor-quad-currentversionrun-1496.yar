rule TTP_XOR_QUAD_CurrentVersionRun_1496 {
  strings:
    $key_1496 = { 47 f9 [2] 63 f7 [2] 48 db [2] 66 f9 [2] 72 e2 [2] 7d f8 [2] 63 e5 [2] 61 e4 [2] 7a e2 [2] 66 e5 [2] 7a ca }

  condition:
    any of them
}