rule TTP_XOR_QUAD_CurrentVersionRun_7696 {
  strings:
    $key_7696 = { 25 f9 [2] 01 f7 [2] 2a db [2] 04 f9 [2] 10 e2 [2] 1f f8 [2] 01 e5 [2] 03 e4 [2] 18 e2 [2] 04 e5 [2] 18 ca }

  condition:
    any of them
}