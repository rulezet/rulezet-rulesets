rule TTP_XOR_MULT_DOSStub_f31e {
  strings:
    $key_f31e = { a7 76 [2] d3 6e [2] 94 6c [2] d3 7d [2] 9d 71 [2] 91 7b [2] 86 70 [2] 9d 3e [2] a0 }

  condition:
    any of them
}