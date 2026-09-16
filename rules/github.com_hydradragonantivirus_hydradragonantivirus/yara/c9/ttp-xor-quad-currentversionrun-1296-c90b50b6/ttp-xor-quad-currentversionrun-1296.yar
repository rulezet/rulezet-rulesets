rule TTP_XOR_QUAD_CurrentVersionRun_1296 {
  strings:
    $key_1296 = { 41 f9 [2] 65 f7 [2] 4e db [2] 60 f9 [2] 74 e2 [2] 7b f8 [2] 65 e5 [2] 67 e4 [2] 7c e2 [2] 60 e5 [2] 7c ca }

  condition:
    any of them
}