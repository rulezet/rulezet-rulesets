rule TTP_XOR_MULT_DOSStub_7629 {
  strings:
    $key_7629 = { 22 41 [2] 56 59 [2] 11 5b [2] 56 4a [2] 18 46 [2] 14 4c [2] 03 47 [2] 18 09 [2] 25 }

  condition:
    any of them
}