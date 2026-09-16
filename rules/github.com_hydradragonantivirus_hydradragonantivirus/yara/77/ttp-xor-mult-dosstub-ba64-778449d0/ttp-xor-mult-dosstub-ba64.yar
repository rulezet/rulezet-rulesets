rule TTP_XOR_MULT_DOSStub_ba64 {
  strings:
    $key_ba64 = { ee 0c [2] 9a 14 [2] dd 16 [2] 9a 07 [2] d4 0b [2] d8 01 [2] cf 0a [2] d4 44 [2] e9 }

  condition:
    any of them
}