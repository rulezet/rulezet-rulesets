rule TTP_XOR_MULT_DOSStub_c335 {
  strings:
    $key_c335 = { 97 5d [2] e3 45 [2] a4 47 [2] e3 56 [2] ad 5a [2] a1 50 [2] b6 5b [2] ad 15 [2] 90 }

  condition:
    any of them
}