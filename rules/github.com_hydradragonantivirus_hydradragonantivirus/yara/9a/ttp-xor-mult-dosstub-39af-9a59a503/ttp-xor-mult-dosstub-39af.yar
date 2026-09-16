rule TTP_XOR_MULT_DOSStub_39af {
  strings:
    $key_39af = { 6d c7 [2] 19 df [2] 5e dd [2] 19 cc [2] 57 c0 [2] 5b ca [2] 4c c1 [2] 57 8f [2] 6a }

  condition:
    any of them
}