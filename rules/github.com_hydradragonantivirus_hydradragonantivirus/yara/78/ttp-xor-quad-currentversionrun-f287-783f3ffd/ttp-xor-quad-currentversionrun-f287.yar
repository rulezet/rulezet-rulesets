rule TTP_XOR_QUAD_CurrentVersionRun_f287 {
  strings:
    $key_f287 = { a1 e8 [2] 85 e6 [2] ae ca [2] 80 e8 [2] 94 f3 [2] 9b e9 [2] 85 f4 [2] 87 f5 [2] 9c f3 [2] 80 f4 [2] 9c db }

  condition:
    any of them
}