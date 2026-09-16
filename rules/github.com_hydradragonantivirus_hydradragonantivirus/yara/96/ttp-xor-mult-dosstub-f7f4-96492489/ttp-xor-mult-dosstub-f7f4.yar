rule TTP_XOR_MULT_DOSStub_f7f4 {
  strings:
    $key_f7f4 = { a3 9c [2] d7 84 [2] 90 86 [2] d7 97 [2] 99 9b [2] 95 91 [2] 82 9a [2] 99 d4 [2] a4 }

  condition:
    any of them
}