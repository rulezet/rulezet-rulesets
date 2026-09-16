rule TTP_XOR_MULT_DOSStub_c322 {
  strings:
    $key_c322 = { 97 4a [2] e3 52 [2] a4 50 [2] e3 41 [2] ad 4d [2] a1 47 [2] b6 4c [2] ad 02 [2] 90 }

  condition:
    any of them
}