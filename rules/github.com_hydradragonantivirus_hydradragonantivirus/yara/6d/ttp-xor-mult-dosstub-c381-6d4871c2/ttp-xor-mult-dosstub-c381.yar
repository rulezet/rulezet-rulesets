rule TTP_XOR_MULT_DOSStub_c381 {
  strings:
    $key_c381 = { 97 e9 [2] e3 f1 [2] a4 f3 [2] e3 e2 [2] ad ee [2] a1 e4 [2] b6 ef [2] ad a1 [2] 90 }

  condition:
    any of them
}