rule TTP_XOR_QUAD_CurrentVersionRun_e296 {
  strings:
    $key_e296 = { b1 f9 [2] 95 f7 [2] be db [2] 90 f9 [2] 84 e2 [2] 8b f8 [2] 95 e5 [2] 97 e4 [2] 8c e2 [2] 90 e5 [2] 8c ca }

  condition:
    any of them
}