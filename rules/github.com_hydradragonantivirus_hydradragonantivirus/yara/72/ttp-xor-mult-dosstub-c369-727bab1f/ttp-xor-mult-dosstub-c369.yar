rule TTP_XOR_MULT_DOSStub_c369 {
  strings:
    $key_c369 = { 97 01 [2] e3 19 [2] a4 1b [2] e3 0a [2] ad 06 [2] a1 0c [2] b6 07 [2] ad 49 [2] 90 }

  condition:
    any of them
}