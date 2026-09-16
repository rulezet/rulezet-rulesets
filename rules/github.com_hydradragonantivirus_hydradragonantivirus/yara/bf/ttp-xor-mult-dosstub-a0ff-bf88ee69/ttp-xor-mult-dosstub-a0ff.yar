rule TTP_XOR_MULT_DOSStub_a0ff {
  strings:
    $key_a0ff = { f4 97 [2] 80 8f [2] c7 8d [2] 80 9c [2] ce 90 [2] c2 9a [2] d5 91 [2] ce df [2] f3 }

  condition:
    any of them
}