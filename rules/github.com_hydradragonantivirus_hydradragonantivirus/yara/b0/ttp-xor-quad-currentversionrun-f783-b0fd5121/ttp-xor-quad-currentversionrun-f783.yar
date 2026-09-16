rule TTP_XOR_QUAD_CurrentVersionRun_f783 {
  strings:
    $key_f783 = { a4 ec [2] 80 e2 [2] ab ce [2] 85 ec [2] 91 f7 [2] 9e ed [2] 80 f0 [2] 82 f1 [2] 99 f7 [2] 85 f0 [2] 99 df }

  condition:
    any of them
}