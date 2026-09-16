rule TTP_XOR_MULT_DOSStub_eea9 {
  strings:
    $key_eea9 = { ba c1 [2] ce d9 [2] 89 db [2] ce ca [2] 80 c6 [2] 8c cc [2] 9b c7 [2] 80 89 [2] bd }

  condition:
    any of them
}