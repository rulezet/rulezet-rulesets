rule TTP_XOR_QUAD_CurrentVersionRun_5d83 {
  strings:
    $key_5d83 = { 0e ec [2] 2a e2 [2] 01 ce [2] 2f ec [2] 3b f7 [2] 34 ed [2] 2a f0 [2] 28 f1 [2] 33 f7 [2] 2f f0 [2] 33 df }

  condition:
    any of them
}