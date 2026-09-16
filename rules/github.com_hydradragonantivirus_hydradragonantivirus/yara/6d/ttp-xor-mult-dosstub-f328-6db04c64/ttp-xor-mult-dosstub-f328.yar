rule TTP_XOR_MULT_DOSStub_f328 {
  strings:
    $key_f328 = { a7 40 [2] d3 58 [2] 94 5a [2] d3 4b [2] 9d 47 [2] 91 4d [2] 86 46 [2] 9d 08 [2] a0 }

  condition:
    any of them
}