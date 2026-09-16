rule TTP_XOR_MULT_DOSStub_ff87 {
  strings:
    $key_ff87 = { ab ef [2] df f7 [2] 98 f5 [2] df e4 [2] 91 e8 [2] 9d e2 [2] 8a e9 [2] 91 a7 [2] ac }

  condition:
    any of them
}