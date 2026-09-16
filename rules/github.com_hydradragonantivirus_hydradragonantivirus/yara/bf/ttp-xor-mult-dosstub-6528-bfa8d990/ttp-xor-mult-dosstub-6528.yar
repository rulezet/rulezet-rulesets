rule TTP_XOR_MULT_DOSStub_6528 {
  strings:
    $key_6528 = { 31 40 [2] 45 58 [2] 02 5a [2] 45 4b [2] 0b 47 [2] 07 4d [2] 10 46 [2] 0b 08 [2] 36 }

  condition:
    any of them
}