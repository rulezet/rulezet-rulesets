rule TTP_XOR_MULT_DOSStub_087c {
  strings:
    $key_087c = { 5c 14 [2] 28 0c [2] 6f 0e [2] 28 1f [2] 66 13 [2] 6a 19 [2] 7d 12 [2] 66 5c [2] 5b }

  condition:
    any of them
}