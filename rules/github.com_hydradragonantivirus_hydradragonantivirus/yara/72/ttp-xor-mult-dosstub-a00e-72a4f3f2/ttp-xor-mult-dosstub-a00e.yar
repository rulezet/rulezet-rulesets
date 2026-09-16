rule TTP_XOR_MULT_DOSStub_a00e {
  strings:
    $key_a00e = { f4 66 [2] 80 7e [2] c7 7c [2] 80 6d [2] ce 61 [2] c2 6b [2] d5 60 [2] ce 2e [2] f3 }

  condition:
    any of them
}