rule TTP_XOR_MULT_DOSStub_ba1f {
  strings:
    $key_ba1f = { ee 77 [2] 9a 6f [2] dd 6d [2] 9a 7c [2] d4 70 [2] d8 7a [2] cf 71 [2] d4 3f [2] e9 }

  condition:
    any of them
}