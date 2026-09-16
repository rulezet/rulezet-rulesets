rule TTP_XOR_MULT_DOSStub_f36d {
  strings:
    $key_f36d = { a7 05 [2] d3 1d [2] 94 1f [2] d3 0e [2] 9d 02 [2] 91 08 [2] 86 03 [2] 9d 4d [2] a0 }

  condition:
    any of them
}