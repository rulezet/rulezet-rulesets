rule TTP_XOR_MULT_DOSStub_f66e {
  strings:
    $key_f66e = { a2 06 [2] d6 1e [2] 91 1c [2] d6 0d [2] 98 01 [2] 94 0b [2] 83 00 [2] 98 4e [2] a5 }

  condition:
    any of them
}