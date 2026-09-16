rule TTP_XOR_MULT_DOSStub_6029 {
  strings:
    $key_6029 = { 34 41 [2] 40 59 [2] 07 5b [2] 40 4a [2] 0e 46 [2] 02 4c [2] 15 47 [2] 0e 09 [2] 33 }

  condition:
    any of them
}