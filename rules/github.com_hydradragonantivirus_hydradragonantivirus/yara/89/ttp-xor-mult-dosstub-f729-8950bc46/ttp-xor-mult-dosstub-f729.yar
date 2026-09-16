rule TTP_XOR_MULT_DOSStub_f729 {
  strings:
    $key_f729 = { a3 41 [2] d7 59 [2] 90 5b [2] d7 4a [2] 99 46 [2] 95 4c [2] 82 47 [2] 99 09 [2] a4 }

  condition:
    any of them
}