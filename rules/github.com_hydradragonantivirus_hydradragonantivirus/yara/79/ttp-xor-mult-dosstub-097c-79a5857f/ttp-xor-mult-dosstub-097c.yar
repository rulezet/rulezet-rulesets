rule TTP_XOR_MULT_DOSStub_097c {
  strings:
    $key_097c = { 5d 14 [2] 29 0c [2] 6e 0e [2] 29 1f [2] 67 13 [2] 6b 19 [2] 7c 12 [2] 67 5c [2] 5a }

  condition:
    any of them
}