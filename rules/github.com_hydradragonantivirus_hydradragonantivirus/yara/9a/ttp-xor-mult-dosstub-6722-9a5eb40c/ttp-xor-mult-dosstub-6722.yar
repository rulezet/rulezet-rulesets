rule TTP_XOR_MULT_DOSStub_6722 {
  strings:
    $key_6722 = { 33 4a [2] 47 52 [2] 00 50 [2] 47 41 [2] 09 4d [2] 05 47 [2] 12 4c [2] 09 02 [2] 34 }

  condition:
    any of them
}