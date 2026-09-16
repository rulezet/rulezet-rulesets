rule TTP_XOR_MULT_DOSStub_f665 {
  strings:
    $key_f665 = { a2 0d [2] d6 15 [2] 91 17 [2] d6 06 [2] 98 0a [2] 94 00 [2] 83 0b [2] 98 45 [2] a5 }

  condition:
    any of them
}