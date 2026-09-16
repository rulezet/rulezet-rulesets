rule TTP_XOR_MULT_DOSStub_6518 {
  strings:
    $key_6518 = { 31 70 [2] 45 68 [2] 02 6a [2] 45 7b [2] 0b 77 [2] 07 7d [2] 10 76 [2] 0b 38 [2] 36 }

  condition:
    any of them
}