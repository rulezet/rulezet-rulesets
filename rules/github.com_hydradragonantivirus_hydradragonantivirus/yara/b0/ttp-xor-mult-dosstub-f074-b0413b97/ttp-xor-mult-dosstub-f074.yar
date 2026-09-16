rule TTP_XOR_MULT_DOSStub_f074 {
  strings:
    $key_f074 = { a4 1c [2] d0 04 [2] 97 06 [2] d0 17 [2] 9e 1b [2] 92 11 [2] 85 1a [2] 9e 54 [2] a3 }

  condition:
    any of them
}