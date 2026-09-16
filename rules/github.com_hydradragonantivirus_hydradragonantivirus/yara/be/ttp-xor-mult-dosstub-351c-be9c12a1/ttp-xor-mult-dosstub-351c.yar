rule TTP_XOR_MULT_DOSStub_351c {
  strings:
    $key_351c = { 61 74 [2] 15 6c [2] 52 6e [2] 15 7f [2] 5b 73 [2] 57 79 [2] 40 72 [2] 5b 3c [2] 66 }

  condition:
    any of them
}