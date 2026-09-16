rule TTP_XOR_MULT_DOSStub_d721 {
  strings:
    $key_d721 = { 83 49 [2] f7 51 [2] b0 53 [2] f7 42 [2] b9 4e [2] b5 44 [2] a2 4f [2] b9 01 [2] 84 }

  condition:
    any of them
}