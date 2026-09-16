rule TTP_XOR_MULT_DOSStub_a035 {
  strings:
    $key_a035 = { f4 5d [2] 80 45 [2] c7 47 [2] 80 56 [2] ce 5a [2] c2 50 [2] d5 5b [2] ce 15 [2] f3 }

  condition:
    any of them
}