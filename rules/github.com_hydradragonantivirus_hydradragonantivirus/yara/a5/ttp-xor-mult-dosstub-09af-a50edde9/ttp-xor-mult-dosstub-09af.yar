rule TTP_XOR_MULT_DOSStub_09af {
  strings:
    $key_09af = { 5d c7 [2] 29 df [2] 6e dd [2] 29 cc [2] 67 c0 [2] 6b ca [2] 7c c1 [2] 67 8f [2] 5a }

  condition:
    any of them
}