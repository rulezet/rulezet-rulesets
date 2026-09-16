rule TTP_XOR_MULT_DOSStub_ba3c {
  strings:
    $key_ba3c = { ee 54 [2] 9a 4c [2] dd 4e [2] 9a 5f [2] d4 53 [2] d8 59 [2] cf 52 [2] d4 1c [2] e9 }

  condition:
    any of them
}