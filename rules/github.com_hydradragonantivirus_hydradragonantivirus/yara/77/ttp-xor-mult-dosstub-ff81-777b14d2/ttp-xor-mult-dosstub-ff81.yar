rule TTP_XOR_MULT_DOSStub_ff81 {
  strings:
    $key_ff81 = { ab e9 [2] df f1 [2] 98 f3 [2] df e2 [2] 91 ee [2] 9d e4 [2] 8a ef [2] 91 a1 [2] ac }

  condition:
    any of them
}