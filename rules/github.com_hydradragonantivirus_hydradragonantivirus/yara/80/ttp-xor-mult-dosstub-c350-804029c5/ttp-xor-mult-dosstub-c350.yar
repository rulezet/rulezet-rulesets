rule TTP_XOR_MULT_DOSStub_c350 {
  strings:
    $key_c350 = { 97 38 [2] e3 20 [2] a4 22 [2] e3 33 [2] ad 3f [2] a1 35 [2] b6 3e [2] ad 70 [2] 90 }

  condition:
    any of them
}