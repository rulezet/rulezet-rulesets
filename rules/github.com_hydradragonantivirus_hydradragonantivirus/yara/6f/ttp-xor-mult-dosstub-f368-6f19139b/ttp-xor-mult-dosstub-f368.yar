rule TTP_XOR_MULT_DOSStub_f368 {
  strings:
    $key_f368 = { a7 00 [2] d3 18 [2] 94 1a [2] d3 0b [2] 9d 07 [2] 91 0d [2] 86 06 [2] 9d 48 [2] a0 }

  condition:
    any of them
}