rule TTP_XOR_MULT_DOSStub_f063 {
  strings:
    $key_f063 = { a4 0b [2] d0 13 [2] 97 11 [2] d0 00 [2] 9e 0c [2] 92 06 [2] 85 0d [2] 9e 43 [2] a3 }

  condition:
    any of them
}