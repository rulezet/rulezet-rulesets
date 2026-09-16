rule TTP_XOR_MULT_DOSStub_6028 {
  strings:
    $key_6028 = { 34 40 [2] 40 58 [2] 07 5a [2] 40 4b [2] 0e 47 [2] 02 4d [2] 15 46 [2] 0e 08 [2] 33 }

  condition:
    any of them
}