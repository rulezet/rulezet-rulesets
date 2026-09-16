rule TTP_XOR_MULT_DOSStub_29af {
  strings:
    $key_29af = { 7d c7 [2] 09 df [2] 4e dd [2] 09 cc [2] 47 c0 [2] 4b ca [2] 5c c1 [2] 47 8f [2] 7a }

  condition:
    any of them
}