rule TTP_XOR_QUAD_CurrentVersionRun_e696 {
  strings:
    $key_e696 = { b5 f9 [2] 91 f7 [2] ba db [2] 94 f9 [2] 80 e2 [2] 8f f8 [2] 91 e5 [2] 93 e4 [2] 88 e2 [2] 94 e5 [2] 88 ca }

  condition:
    any of them
}