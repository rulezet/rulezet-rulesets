rule TTP_XOR_MULT_DOSStub_5e63 {
  strings:
    $key_5e63 = { 0a 0b [2] 7e 13 [2] 39 11 [2] 7e 00 [2] 30 0c [2] 3c 06 [2] 2b 0d [2] 30 43 [2] 0d }

  condition:
    any of them
}