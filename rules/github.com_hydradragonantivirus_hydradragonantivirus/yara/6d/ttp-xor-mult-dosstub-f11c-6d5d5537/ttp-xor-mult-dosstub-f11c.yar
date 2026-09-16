rule TTP_XOR_MULT_DOSStub_f11c {
  strings:
    $key_f11c = { a5 74 [2] d1 6c [2] 96 6e [2] d1 7f [2] 9f 73 [2] 93 79 [2] 84 72 [2] 9f 3c [2] a2 }

  condition:
    any of them
}