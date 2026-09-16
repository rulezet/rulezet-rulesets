rule TTP_XOR_MULT_DOSStub_f668 {
  strings:
    $key_f668 = { a2 00 [2] d6 18 [2] 91 1a [2] d6 0b [2] 98 07 [2] 94 0d [2] 83 06 [2] 98 48 [2] a5 }

  condition:
    any of them
}