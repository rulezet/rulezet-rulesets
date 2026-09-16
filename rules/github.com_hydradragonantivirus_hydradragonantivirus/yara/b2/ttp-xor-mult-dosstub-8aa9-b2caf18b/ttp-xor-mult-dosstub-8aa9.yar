rule TTP_XOR_MULT_DOSStub_8aa9 {
  strings:
    $key_8aa9 = { de c1 [2] aa d9 [2] ed db [2] aa ca [2] e4 c6 [2] e8 cc [2] ff c7 [2] e4 89 [2] d9 }

  condition:
    any of them
}