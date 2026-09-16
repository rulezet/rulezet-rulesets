rule TTP_XOR_MULT_DOSStub_e881 {
  strings:
    $key_e881 = { bc e9 [2] c8 f1 [2] 8f f3 [2] c8 e2 [2] 86 ee [2] 8a e4 [2] 9d ef [2] 86 a1 [2] bb }

  condition:
    any of them
}