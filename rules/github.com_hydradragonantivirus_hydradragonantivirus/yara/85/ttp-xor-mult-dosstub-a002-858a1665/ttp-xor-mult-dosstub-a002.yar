rule TTP_XOR_MULT_DOSStub_a002 {
  strings:
    $key_a002 = { f4 6a [2] 80 72 [2] c7 70 [2] 80 61 [2] ce 6d [2] c2 67 [2] d5 6c [2] ce 22 [2] f3 }

  condition:
    any of them
}