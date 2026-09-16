rule TTP_XOR_QUAD_CurrentVersionRun_2b83 {
  strings:
    $key_2b83 = { 78 ec [2] 5c e2 [2] 77 ce [2] 59 ec [2] 4d f7 [2] 42 ed [2] 5c f0 [2] 5e f1 [2] 45 f7 [2] 59 f0 [2] 45 df }

  condition:
    any of them
}