rule TTP_XOR_MULT_DOSStub_d717 {
  strings:
    $key_d717 = { 83 7f [2] f7 67 [2] b0 65 [2] f7 74 [2] b9 78 [2] b5 72 [2] a2 79 [2] b9 37 [2] 84 }

  condition:
    any of them
}