rule TTP_XOR_MULT_DOSStub_f764 {
  strings:
    $key_f764 = { a3 0c [2] d7 14 [2] 90 16 [2] d7 07 [2] 99 0b [2] 95 01 [2] 82 0a [2] 99 44 [2] a4 }

  condition:
    any of them
}