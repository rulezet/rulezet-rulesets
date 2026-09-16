rule TTP_XOR_MULT_DOSStub_2b9d {
  strings:
    $key_2b9d = { 7f f5 [2] 0b ed [2] 4c ef [2] 0b fe [2] 45 f2 [2] 49 f8 [2] 5e f3 [2] 45 bd [2] 78 }

  condition:
    any of them
}