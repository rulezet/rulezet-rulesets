rule TTP_XOR_MULT_DOSStub_a02a {
  strings:
    $key_a02a = { f4 42 [2] 80 5a [2] c7 58 [2] 80 49 [2] ce 45 [2] c2 4f [2] d5 44 [2] ce 0a [2] f3 }

  condition:
    any of them
}