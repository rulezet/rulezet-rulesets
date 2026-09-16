rule TTP_XOR_MULT_DOSStub_c9af {
  strings:
    $key_c9af = { 9d c7 [2] e9 df [2] ae dd [2] e9 cc [2] a7 c0 [2] ab ca [2] bc c1 [2] a7 8f [2] 9a }

  condition:
    any of them
}