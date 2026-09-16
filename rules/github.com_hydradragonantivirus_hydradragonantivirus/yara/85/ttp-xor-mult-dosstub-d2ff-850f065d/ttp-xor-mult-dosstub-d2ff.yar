rule TTP_XOR_MULT_DOSStub_d2ff {
  strings:
    $key_d2ff = { 86 97 [2] f2 8f [2] b5 8d [2] f2 9c [2] bc 90 [2] b0 9a [2] a7 91 [2] bc df [2] 81 }

  condition:
    any of them
}