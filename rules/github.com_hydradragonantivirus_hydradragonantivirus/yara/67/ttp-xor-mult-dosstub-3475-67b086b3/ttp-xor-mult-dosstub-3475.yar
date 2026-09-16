rule TTP_XOR_MULT_DOSStub_3475 {
  strings:
    $key_3475 = { 60 1d [2] 14 05 [2] 53 07 [2] 14 16 [2] 5a 1a [2] 56 10 [2] 41 1b [2] 5a 55 [2] 67 }

  condition:
    any of them
}