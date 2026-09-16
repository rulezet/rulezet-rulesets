rule TTP_XOR_MULT_DOSStub_223c {
  strings:
    $key_223c = { 76 54 [2] 02 4c [2] 45 4e [2] 02 5f [2] 4c 53 [2] 40 59 [2] 57 52 [2] 4c 1c [2] 71 }

  condition:
    any of them
}