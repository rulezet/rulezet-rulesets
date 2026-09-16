rule TTP_XOR_MULT_DOSStub_f338 {
  strings:
    $key_f338 = { a7 50 [2] d3 48 [2] 94 4a [2] d3 5b [2] 9d 57 [2] 91 5d [2] 86 56 [2] 9d 18 [2] a0 }

  condition:
    any of them
}