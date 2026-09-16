rule TTP_XOR_MULT_DOSStub_f329 {
  strings:
    $key_f329 = { a7 41 [2] d3 59 [2] 94 5b [2] d3 4a [2] 9d 46 [2] 91 4c [2] 86 47 [2] 9d 09 [2] a0 }

  condition:
    any of them
}