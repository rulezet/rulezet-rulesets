rule TTP_XOR_MULT_DOSStub_f26e {
  strings:
    $key_f26e = { a6 06 [2] d2 1e [2] 95 1c [2] d2 0d [2] 9c 01 [2] 90 0b [2] 87 00 [2] 9c 4e [2] a1 }

  condition:
    any of them
}