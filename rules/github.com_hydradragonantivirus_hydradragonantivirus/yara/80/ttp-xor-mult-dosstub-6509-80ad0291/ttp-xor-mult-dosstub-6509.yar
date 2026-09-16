rule TTP_XOR_MULT_DOSStub_6509 {
  strings:
    $key_6509 = { 31 61 [2] 45 79 [2] 02 7b [2] 45 6a [2] 0b 66 [2] 07 6c [2] 10 67 [2] 0b 29 [2] 36 }

  condition:
    any of them
}