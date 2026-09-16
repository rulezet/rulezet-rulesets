rule TTP_XOR_QUAD_CurrentVersionRun_e483 {
  strings:
    $key_e483 = { b7 ec [2] 93 e2 [2] b8 ce [2] 96 ec [2] 82 f7 [2] 8d ed [2] 93 f0 [2] 91 f1 [2] 8a f7 [2] 96 f0 [2] 8a df }

  condition:
    any of them
}