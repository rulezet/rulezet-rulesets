rule TTP_XOR_MULT_DOSStub_c362 {
  strings:
    $key_c362 = { 97 0a [2] e3 12 [2] a4 10 [2] e3 01 [2] ad 0d [2] a1 07 [2] b6 0c [2] ad 42 [2] 90 }

  condition:
    any of them
}