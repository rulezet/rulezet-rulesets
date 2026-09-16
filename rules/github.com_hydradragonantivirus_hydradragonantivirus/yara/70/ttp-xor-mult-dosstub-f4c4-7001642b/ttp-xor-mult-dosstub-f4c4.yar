rule TTP_XOR_MULT_DOSStub_f4c4 {
  strings:
    $key_f4c4 = { a0 ac [2] d4 b4 [2] 93 b6 [2] d4 a7 [2] 9a ab [2] 96 a1 [2] 81 aa [2] 9a e4 [2] a7 }

  condition:
    any of them
}