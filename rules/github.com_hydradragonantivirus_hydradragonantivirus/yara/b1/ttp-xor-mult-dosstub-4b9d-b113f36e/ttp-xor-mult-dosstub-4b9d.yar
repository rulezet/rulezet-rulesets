rule TTP_XOR_MULT_DOSStub_4b9d {
  strings:
    $key_4b9d = { 1f f5 [2] 6b ed [2] 2c ef [2] 6b fe [2] 25 f2 [2] 29 f8 [2] 3e f3 [2] 25 bd [2] 18 }

  condition:
    any of them
}