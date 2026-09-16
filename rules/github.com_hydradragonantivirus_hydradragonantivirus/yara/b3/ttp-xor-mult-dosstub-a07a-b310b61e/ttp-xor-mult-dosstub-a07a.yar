rule TTP_XOR_MULT_DOSStub_a07a {
  strings:
    $key_a07a = { f4 12 [2] 80 0a [2] c7 08 [2] 80 19 [2] ce 15 [2] c2 1f [2] d5 14 [2] ce 5a [2] f3 }

  condition:
    any of them
}