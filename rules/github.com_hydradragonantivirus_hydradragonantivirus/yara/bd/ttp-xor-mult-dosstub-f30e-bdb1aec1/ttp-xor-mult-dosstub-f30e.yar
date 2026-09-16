rule TTP_XOR_MULT_DOSStub_f30e {
  strings:
    $key_f30e = { a7 66 [2] d3 7e [2] 94 7c [2] d3 6d [2] 9d 61 [2] 91 6b [2] 86 60 [2] 9d 2e [2] a0 }

  condition:
    any of them
}