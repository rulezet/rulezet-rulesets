rule TTP_XOR_QUAD_CurrentVersionRun_f885 {
  strings:
    $key_f885 = { ab ea [2] 8f e4 [2] a4 c8 [2] 8a ea [2] 9e f1 [2] 91 eb [2] 8f f6 [2] 8d f7 [2] 96 f1 [2] 8a f6 [2] 96 d9 }

  condition:
    any of them
}