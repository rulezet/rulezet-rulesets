rule TTP_XOR_MULT_DOSStub_f37b {
  strings:
    $key_f37b = { a7 13 [2] d3 0b [2] 94 09 [2] d3 18 [2] 9d 14 [2] 91 1e [2] 86 15 [2] 9d 5b [2] a0 }

  condition:
    any of them
}