rule TTP_XOR_MULT_DOSStub_f326 {
  strings:
    $key_f326 = { a7 4e [2] d3 56 [2] 94 54 [2] d3 45 [2] 9d 49 [2] 91 43 [2] 86 48 [2] 9d 06 [2] a0 }

  condition:
    any of them
}