rule TTP_XOR_MULT_DOSStub_a0fc {
  strings:
    $key_a0fc = { f4 94 [2] 80 8c [2] c7 8e [2] 80 9f [2] ce 93 [2] c2 99 [2] d5 92 [2] ce dc [2] f3 }

  condition:
    any of them
}