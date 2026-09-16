rule TTP_XOR_QUAD_CurrentVersionRun_2483 {
  strings:
    $key_2483 = { 77 ec [2] 53 e2 [2] 78 ce [2] 56 ec [2] 42 f7 [2] 4d ed [2] 53 f0 [2] 51 f1 [2] 4a f7 [2] 56 f0 [2] 4a df }

  condition:
    any of them
}