rule TTP_XOR_MULT_DOSStub_3e17 {
  strings:
    $key_3e17 = { 6a 7f [2] 1e 67 [2] 59 65 [2] 1e 74 [2] 50 78 [2] 5c 72 [2] 4b 79 [2] 50 37 [2] 6d }

  condition:
    any of them
}