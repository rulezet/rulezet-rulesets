rule TTP_XOR_MULT_DOSStub_c323 {
  strings:
    $key_c323 = { 97 4b [2] e3 53 [2] a4 51 [2] e3 40 [2] ad 4c [2] a1 46 [2] b6 4d [2] ad 03 [2] 90 }

  condition:
    any of them
}