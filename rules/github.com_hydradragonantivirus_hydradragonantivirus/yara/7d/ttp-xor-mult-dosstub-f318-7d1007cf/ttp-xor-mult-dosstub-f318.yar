rule TTP_XOR_MULT_DOSStub_f318 {
  strings:
    $key_f318 = { a7 70 [2] d3 68 [2] 94 6a [2] d3 7b [2] 9d 77 [2] 91 7d [2] 86 76 [2] 9d 38 [2] a0 }

  condition:
    any of them
}