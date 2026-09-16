rule TTP_XOR_MULT_DOSStub_f881 {
  strings:
    $key_f881 = { ac e9 [2] d8 f1 [2] 9f f3 [2] d8 e2 [2] 96 ee [2] 9a e4 [2] 8d ef [2] 96 a1 [2] ab }

  condition:
    any of them
}