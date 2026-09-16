rule TTP_XOR_MULT_DOSStub_f7e8 {
  strings:
    $key_f7e8 = { a3 80 [2] d7 98 [2] 90 9a [2] d7 8b [2] 99 87 [2] 95 8d [2] 82 86 [2] 99 c8 [2] a4 }

  condition:
    any of them
}