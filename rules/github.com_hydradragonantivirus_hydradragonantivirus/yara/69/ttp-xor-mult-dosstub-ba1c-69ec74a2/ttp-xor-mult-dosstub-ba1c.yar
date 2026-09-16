rule TTP_XOR_MULT_DOSStub_ba1c {
  strings:
    $key_ba1c = { ee 74 [2] 9a 6c [2] dd 6e [2] 9a 7f [2] d4 73 [2] d8 79 [2] cf 72 [2] d4 3c [2] e9 }

  condition:
    any of them
}