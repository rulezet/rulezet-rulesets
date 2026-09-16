rule TTP_XOR_MULT_DOSStub_a02b {
  strings:
    $key_a02b = { f4 43 [2] 80 5b [2] c7 59 [2] 80 48 [2] ce 44 [2] c2 4e [2] d5 45 [2] ce 0b [2] f3 }

  condition:
    any of them
}