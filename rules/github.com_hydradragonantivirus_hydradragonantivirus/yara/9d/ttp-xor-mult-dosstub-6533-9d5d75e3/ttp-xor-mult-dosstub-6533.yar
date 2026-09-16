rule TTP_XOR_MULT_DOSStub_6533 {
  strings:
    $key_6533 = { 31 5b [2] 45 43 [2] 02 41 [2] 45 50 [2] 0b 5c [2] 07 56 [2] 10 5d [2] 0b 13 [2] 36 }

  condition:
    any of them
}