rule TTP_XOR_MULT_DOSStub_d4f9 {
  strings:
    $key_d4f9 = { 80 91 [2] f4 89 [2] b3 8b [2] f4 9a [2] ba 96 [2] b6 9c [2] a1 97 [2] ba d9 [2] 87 }

  condition:
    any of them
}