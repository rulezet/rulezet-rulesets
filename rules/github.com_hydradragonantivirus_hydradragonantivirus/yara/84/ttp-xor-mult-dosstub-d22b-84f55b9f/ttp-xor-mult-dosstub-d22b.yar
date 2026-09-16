rule TTP_XOR_MULT_DOSStub_d22b {
  strings:
    $key_d22b = { 86 43 [2] f2 5b [2] b5 59 [2] f2 48 [2] bc 44 [2] b0 4e [2] a7 45 [2] bc 0b [2] 81 }

  condition:
    any of them
}