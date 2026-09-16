rule TTP_XOR_MULT_DOSStub_baff {
  strings:
    $key_baff = { ee 97 [2] 9a 8f [2] dd 8d [2] 9a 9c [2] d4 90 [2] d8 9a [2] cf 91 [2] d4 df [2] e9 }

  condition:
    any of them
}