rule TTP_XOR_MULT_DOSStub_f34c {
  strings:
    $key_f34c = { a7 24 [2] d3 3c [2] 94 3e [2] d3 2f [2] 9d 23 [2] 91 29 [2] 86 22 [2] 9d 6c [2] a0 }

  condition:
    any of them
}