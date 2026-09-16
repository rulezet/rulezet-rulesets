rule TTP_XOR_MULT_DOSStub_a020 {
  strings:
    $key_a020 = { f4 48 [2] 80 50 [2] c7 52 [2] 80 43 [2] ce 4f [2] c2 45 [2] d5 4e [2] ce 00 [2] f3 }

  condition:
    any of them
}