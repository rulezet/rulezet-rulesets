rule TTP_XOR_MULT_DOSStub_f722 {
  strings:
    $key_f722 = { a3 4a [2] d7 52 [2] 90 50 [2] d7 41 [2] 99 4d [2] 95 47 [2] 82 4c [2] 99 02 [2] a4 }

  condition:
    any of them
}