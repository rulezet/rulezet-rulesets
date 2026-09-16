rule TTP_XOR_MULT_DOSStub_f71c {
  strings:
    $key_f71c = { a3 74 [2] d7 6c [2] 90 6e [2] d7 7f [2] 99 73 [2] 95 79 [2] 82 72 [2] 99 3c [2] a4 }

  condition:
    any of them
}