rule TTP_XOR_MULT_DOSStub_ba2f {
  strings:
    $key_ba2f = { ee 47 [2] 9a 5f [2] dd 5d [2] 9a 4c [2] d4 40 [2] d8 4a [2] cf 41 [2] d4 0f [2] e9 }

  condition:
    any of them
}