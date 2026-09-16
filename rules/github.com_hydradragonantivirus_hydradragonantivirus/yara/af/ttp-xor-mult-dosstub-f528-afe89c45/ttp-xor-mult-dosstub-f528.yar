rule TTP_XOR_MULT_DOSStub_f528 {
  strings:
    $key_f528 = { a1 40 [2] d5 58 [2] 92 5a [2] d5 4b [2] 9b 47 [2] 97 4d [2] 80 46 [2] 9b 08 [2] a6 }

  condition:
    any of them
}