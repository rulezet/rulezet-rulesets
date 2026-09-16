rule TTP_XOR_MULT_DOSStub_c237 {
  strings:
    $key_c237 = { 96 5f [2] e2 47 [2] a5 45 [2] e2 54 [2] ac 58 [2] a0 52 [2] b7 59 [2] ac 17 [2] 91 }

  condition:
    any of them
}