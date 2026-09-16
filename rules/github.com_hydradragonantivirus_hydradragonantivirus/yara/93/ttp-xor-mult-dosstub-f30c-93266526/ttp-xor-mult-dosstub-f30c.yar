rule TTP_XOR_MULT_DOSStub_f30c {
  strings:
    $key_f30c = { a7 64 [2] d3 7c [2] 94 7e [2] d3 6f [2] 9d 63 [2] 91 69 [2] 86 62 [2] 9d 2c [2] a0 }

  condition:
    any of them
}