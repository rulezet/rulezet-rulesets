rule TTP_XOR_MULT_DOSStub_baed {
  strings:
    $key_baed = { ee 85 [2] 9a 9d [2] dd 9f [2] 9a 8e [2] d4 82 [2] d8 88 [2] cf 83 [2] d4 cd [2] e9 }

  condition:
    any of them
}