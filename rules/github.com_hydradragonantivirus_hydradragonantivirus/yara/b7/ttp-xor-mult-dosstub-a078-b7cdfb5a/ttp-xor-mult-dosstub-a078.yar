rule TTP_XOR_MULT_DOSStub_a078 {
  strings:
    $key_a078 = { f4 10 [2] 80 08 [2] c7 0a [2] 80 1b [2] ce 17 [2] c2 1d [2] d5 16 [2] ce 58 [2] f3 }

  condition:
    any of them
}