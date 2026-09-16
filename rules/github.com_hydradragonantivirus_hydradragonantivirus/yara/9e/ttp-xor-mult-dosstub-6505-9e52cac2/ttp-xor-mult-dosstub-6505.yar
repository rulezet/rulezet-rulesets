rule TTP_XOR_MULT_DOSStub_6505 {
  strings:
    $key_6505 = { 31 6d [2] 45 75 [2] 02 77 [2] 45 66 [2] 0b 6a [2] 07 60 [2] 10 6b [2] 0b 25 [2] 36 }

  condition:
    any of them
}