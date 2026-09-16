rule TTP_XOR_MULT_DOSStub_f529 {
  strings:
    $key_f529 = { a1 41 [2] d5 59 [2] 92 5b [2] d5 4a [2] 9b 46 [2] 97 4c [2] 80 47 [2] 9b 09 [2] a6 }

  condition:
    any of them
}