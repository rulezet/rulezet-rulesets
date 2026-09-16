rule TTP_XOR_MULT_DOSStub_a01f {
  strings:
    $key_a01f = { f4 77 [2] 80 6f [2] c7 6d [2] 80 7c [2] ce 70 [2] c2 7a [2] d5 71 [2] ce 3f [2] f3 }

  condition:
    any of them
}