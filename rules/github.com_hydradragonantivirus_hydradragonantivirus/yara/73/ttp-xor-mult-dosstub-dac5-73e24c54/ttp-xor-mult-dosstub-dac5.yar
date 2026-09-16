rule TTP_XOR_MULT_DOSStub_dac5 {
  strings:
    $key_dac5 = { 8e ad [2] fa b5 [2] bd b7 [2] fa a6 [2] b4 aa [2] b8 a0 [2] af ab [2] b4 e5 [2] 89 }

  condition:
    any of them
}