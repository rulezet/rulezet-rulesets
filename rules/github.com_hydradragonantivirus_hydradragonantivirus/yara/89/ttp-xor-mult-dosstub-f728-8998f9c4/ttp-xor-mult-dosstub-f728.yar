rule TTP_XOR_MULT_DOSStub_f728 {
  strings:
    $key_f728 = { a3 40 [2] d7 58 [2] 90 5a [2] d7 4b [2] 99 47 [2] 95 4d [2] 82 46 [2] 99 08 [2] a4 }

  condition:
    any of them
}