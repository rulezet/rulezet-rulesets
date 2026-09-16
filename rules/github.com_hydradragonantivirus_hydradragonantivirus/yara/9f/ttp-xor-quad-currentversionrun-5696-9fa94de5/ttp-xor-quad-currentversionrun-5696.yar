rule TTP_XOR_QUAD_CurrentVersionRun_5696 {
  strings:
    $key_5696 = { 05 f9 [2] 21 f7 [2] 0a db [2] 24 f9 [2] 30 e2 [2] 3f f8 [2] 21 e5 [2] 23 e4 [2] 38 e2 [2] 24 e5 [2] 38 ca }

  condition:
    any of them
}