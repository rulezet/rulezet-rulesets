rule TTP_XOR_MULT_DOSStub_a01b {
  strings:
    $key_a01b = { f4 73 [2] 80 6b [2] c7 69 [2] 80 78 [2] ce 74 [2] c2 7e [2] d5 75 [2] ce 3b [2] f3 }

  condition:
    any of them
}