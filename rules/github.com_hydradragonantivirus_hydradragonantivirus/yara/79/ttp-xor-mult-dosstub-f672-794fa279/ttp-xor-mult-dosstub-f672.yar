rule TTP_XOR_MULT_DOSStub_f672 {
  strings:
    $key_f672 = { a2 1a [2] d6 02 [2] 91 00 [2] d6 11 [2] 98 1d [2] 94 17 [2] 83 1c [2] 98 52 [2] a5 }

  condition:
    any of them
}