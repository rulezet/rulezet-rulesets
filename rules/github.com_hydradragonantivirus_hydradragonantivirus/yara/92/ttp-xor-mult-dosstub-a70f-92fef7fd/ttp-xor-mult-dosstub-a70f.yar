rule TTP_XOR_MULT_DOSStub_a70f {
  strings:
    $key_a70f = { f3 67 [2] 87 7f [2] c0 7d [2] 87 6c [2] c9 60 [2] c5 6a [2] d2 61 [2] c9 2f [2] f4 }

  condition:
    any of them
}