rule TTP_XOR_MULT_DOSStub_5b9d {
  strings:
    $key_5b9d = { 0f f5 [2] 7b ed [2] 3c ef [2] 7b fe [2] 35 f2 [2] 39 f8 [2] 2e f3 [2] 35 bd [2] 08 }

  condition:
    any of them
}