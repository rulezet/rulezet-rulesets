rule TTP_XOR_MULT_DOSStub_3b9d {
  strings:
    $key_3b9d = { 6f f5 [2] 1b ed [2] 5c ef [2] 1b fe [2] 55 f2 [2] 59 f8 [2] 4e f3 [2] 55 bd [2] 68 }

  condition:
    any of them
}