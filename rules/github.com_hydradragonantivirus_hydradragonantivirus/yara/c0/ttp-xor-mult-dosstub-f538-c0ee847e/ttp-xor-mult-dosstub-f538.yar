rule TTP_XOR_MULT_DOSStub_f538 {
  strings:
    $key_f538 = { a1 50 [2] d5 48 [2] 92 4a [2] d5 5b [2] 9b 57 [2] 97 5d [2] 80 56 [2] 9b 18 [2] a6 }

  condition:
    any of them
}