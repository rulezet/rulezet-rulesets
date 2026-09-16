rule TTP_XOR_MULT_DOSStub_f06e {
  strings:
    $key_f06e = { a4 06 [2] d0 1e [2] 97 1c [2] d0 0d [2] 9e 01 [2] 92 0b [2] 85 00 [2] 9e 4e [2] a3 }

  condition:
    any of them
}