rule TTP_XOR_MULT_DOSStub_c35c {
  strings:
    $key_c35c = { 97 34 [2] e3 2c [2] a4 2e [2] e3 3f [2] ad 33 [2] a1 39 [2] b6 32 [2] ad 7c [2] 90 }

  condition:
    any of them
}