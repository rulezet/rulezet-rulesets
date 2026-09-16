rule TTP_XOR_MULT_DOSStub_c329 {
  strings:
    $key_c329 = { 97 41 [2] e3 59 [2] a4 5b [2] e3 4a [2] ad 46 [2] a1 4c [2] b6 47 [2] ad 09 [2] 90 }

  condition:
    any of them
}