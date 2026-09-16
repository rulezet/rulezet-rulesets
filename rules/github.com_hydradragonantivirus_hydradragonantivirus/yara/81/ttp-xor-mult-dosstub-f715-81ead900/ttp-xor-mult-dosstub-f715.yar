rule TTP_XOR_MULT_DOSStub_f715 {
  strings:
    $key_f715 = { a3 7d [2] d7 65 [2] 90 67 [2] d7 76 [2] 99 7a [2] 95 70 [2] 82 7b [2] 99 35 [2] a4 }

  condition:
    any of them
}