rule TTP_XOR_MULT_DOSStub_c525 {
  strings:
    $key_c525 = { 91 4d [2] e5 55 [2] a2 57 [2] e5 46 [2] ab 4a [2] a7 40 [2] b0 4b [2] ab 05 [2] 96 }

  condition:
    any of them
}