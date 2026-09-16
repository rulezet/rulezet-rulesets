rule TTP_XOR_MULT_DOSStub_f763 {
  strings:
    $key_f763 = { a3 0b [2] d7 13 [2] 90 11 [2] d7 00 [2] 99 0c [2] 95 06 [2] 82 0d [2] 99 43 [2] a4 }

  condition:
    any of them
}