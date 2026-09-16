rule TTP_XOR_MULT_DOSStub_c328 {
  strings:
    $key_c328 = { 97 40 [2] e3 58 [2] a4 5a [2] e3 4b [2] ad 47 [2] a1 4d [2] b6 46 [2] ad 08 [2] 90 }

  condition:
    any of them
}