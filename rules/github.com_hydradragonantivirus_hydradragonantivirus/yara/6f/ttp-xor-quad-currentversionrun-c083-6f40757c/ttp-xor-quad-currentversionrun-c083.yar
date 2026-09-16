rule TTP_XOR_QUAD_CurrentVersionRun_c083 {
  strings:
    $key_c083 = { 93 ec [2] b7 e2 [2] 9c ce [2] b2 ec [2] a6 f7 [2] a9 ed [2] b7 f0 [2] b5 f1 [2] ae f7 [2] b2 f0 [2] ae df }

  condition:
    any of them
}