rule TTP_XOR_MULT_DOSStub_d430 {
  strings:
    $key_d430 = { 80 58 [2] f4 40 [2] b3 42 [2] f4 53 [2] ba 5f [2] b6 55 [2] a1 5e [2] ba 10 [2] 87 }

  condition:
    any of them
}