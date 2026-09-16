rule TTP_XOR_MULT_DOSStub_f36b {
  strings:
    $key_f36b = { a7 03 [2] d3 1b [2] 94 19 [2] d3 08 [2] 9d 04 [2] 91 0e [2] 86 05 [2] 9d 4b [2] a0 }

  condition:
    any of them
}