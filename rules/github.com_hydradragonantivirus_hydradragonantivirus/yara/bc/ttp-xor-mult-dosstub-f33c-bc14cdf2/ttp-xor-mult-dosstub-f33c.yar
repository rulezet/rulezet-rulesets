rule TTP_XOR_MULT_DOSStub_f33c {
  strings:
    $key_f33c = { a7 54 [2] d3 4c [2] 94 4e [2] d3 5f [2] 9d 53 [2] 91 59 [2] 86 52 [2] 9d 1c [2] a0 }

  condition:
    any of them
}