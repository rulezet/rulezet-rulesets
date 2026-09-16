rule TTP_XOR_QUAD_CurrentVersionRun_d083 {
  strings:
    $key_d083 = { 83 ec [2] a7 e2 [2] 8c ce [2] a2 ec [2] b6 f7 [2] b9 ed [2] a7 f0 [2] a5 f1 [2] be f7 [2] a2 f0 [2] be df }

  condition:
    any of them
}