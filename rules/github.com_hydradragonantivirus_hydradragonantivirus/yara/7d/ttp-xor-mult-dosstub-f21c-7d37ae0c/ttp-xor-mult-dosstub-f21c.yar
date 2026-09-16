rule TTP_XOR_MULT_DOSStub_f21c {
  strings:
    $key_f21c = { a6 74 [2] d2 6c [2] 95 6e [2] d2 7f [2] 9c 73 [2] 90 79 [2] 87 72 [2] 9c 3c [2] a1 }

  condition:
    any of them
}