rule TTP_XOR_MULT_DOSStub_d7e5 {
  strings:
    $key_d7e5 = { 83 8d [2] f7 95 [2] b0 97 [2] f7 86 [2] b9 8a [2] b5 80 [2] a2 8b [2] b9 c5 [2] 84 }

  condition:
    any of them
}