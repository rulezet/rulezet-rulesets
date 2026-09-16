rule TTP_XOR_MULT_DOSStub_a00f {
  strings:
    $key_a00f = { f4 67 [2] 80 7f [2] c7 7d [2] 80 6c [2] ce 60 [2] c2 6a [2] d5 61 [2] ce 2f [2] f3 }

  condition:
    any of them
}