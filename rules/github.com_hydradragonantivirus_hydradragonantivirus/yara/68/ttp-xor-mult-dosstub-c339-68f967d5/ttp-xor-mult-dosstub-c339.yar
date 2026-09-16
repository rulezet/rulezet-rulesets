rule TTP_XOR_MULT_DOSStub_c339 {
  strings:
    $key_c339 = { 97 51 [2] e3 49 [2] a4 4b [2] e3 5a [2] ad 56 [2] a1 5c [2] b6 57 [2] ad 19 [2] 90 }

  condition:
    any of them
}