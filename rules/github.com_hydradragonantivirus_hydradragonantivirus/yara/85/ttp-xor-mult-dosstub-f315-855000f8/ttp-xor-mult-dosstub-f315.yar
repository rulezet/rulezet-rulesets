rule TTP_XOR_MULT_DOSStub_f315 {
  strings:
    $key_f315 = { a7 7d [2] d3 65 [2] 94 67 [2] d3 76 [2] 9d 7a [2] 91 70 [2] 86 7b [2] 9d 35 [2] a0 }

  condition:
    any of them
}