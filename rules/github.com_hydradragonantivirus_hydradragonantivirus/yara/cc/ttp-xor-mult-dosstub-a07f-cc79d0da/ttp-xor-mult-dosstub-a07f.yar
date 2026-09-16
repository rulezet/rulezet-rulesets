rule TTP_XOR_MULT_DOSStub_a07f {
  strings:
    $key_a07f = { f4 17 [2] 80 0f [2] c7 0d [2] 80 1c [2] ce 10 [2] c2 1a [2] d5 11 [2] ce 5f [2] f3 }

  condition:
    any of them
}