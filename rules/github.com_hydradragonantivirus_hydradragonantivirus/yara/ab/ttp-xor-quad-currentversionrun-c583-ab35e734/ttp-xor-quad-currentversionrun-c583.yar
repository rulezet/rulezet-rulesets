rule TTP_XOR_QUAD_CurrentVersionRun_c583 {
  strings:
    $key_c583 = { 96 ec [2] b2 e2 [2] 99 ce [2] b7 ec [2] a3 f7 [2] ac ed [2] b2 f0 [2] b0 f1 [2] ab f7 [2] b7 f0 [2] ab df }

  condition:
    any of them
}