rule TTP_XOR_MULT_DOSStub_f579 {
  strings:
    $key_f579 = { a1 11 [2] d5 09 [2] 92 0b [2] d5 1a [2] 9b 16 [2] 97 1c [2] 80 17 [2] 9b 59 [2] a6 }

  condition:
    any of them
}