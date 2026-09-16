rule TTP_XOR_MULT_DOSStub_a02f {
  strings:
    $key_a02f = { f4 47 [2] 80 5f [2] c7 5d [2] 80 4c [2] ce 40 [2] c2 4a [2] d5 41 [2] ce 0f [2] f3 }

  condition:
    any of them
}