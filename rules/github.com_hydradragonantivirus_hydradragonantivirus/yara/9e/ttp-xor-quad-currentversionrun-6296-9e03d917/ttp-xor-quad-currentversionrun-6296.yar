rule TTP_XOR_QUAD_CurrentVersionRun_6296 {
  strings:
    $key_6296 = { 31 f9 [2] 15 f7 [2] 3e db [2] 10 f9 [2] 04 e2 [2] 0b f8 [2] 15 e5 [2] 17 e4 [2] 0c e2 [2] 10 e5 [2] 0c ca }

  condition:
    any of them
}