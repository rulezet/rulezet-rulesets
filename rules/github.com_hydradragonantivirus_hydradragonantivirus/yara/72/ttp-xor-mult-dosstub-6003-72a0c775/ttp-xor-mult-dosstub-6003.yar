rule TTP_XOR_MULT_DOSStub_6003 {
  strings:
    $key_6003 = { 34 6b [2] 40 73 [2] 07 71 [2] 40 60 [2] 0e 6c [2] 02 66 [2] 15 6d [2] 0e 23 [2] 33 }

  condition:
    any of them
}