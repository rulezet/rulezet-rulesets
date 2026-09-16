rule TTP_XOR_MULT_DOSStub_0b9d {
  strings:
    $key_0b9d = { 5f f5 [2] 2b ed [2] 6c ef [2] 2b fe [2] 65 f2 [2] 69 f8 [2] 7e f3 [2] 65 bd [2] 58 }

  condition:
    any of them
}