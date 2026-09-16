rule TTP_XOR_MULT_DOSStub_f5e3 {
  strings:
    $key_f5e3 = { a1 8b [2] d5 93 [2] 92 91 [2] d5 80 [2] 9b 8c [2] 97 86 [2] 80 8d [2] 9b c3 [2] a6 }

  condition:
    any of them
}