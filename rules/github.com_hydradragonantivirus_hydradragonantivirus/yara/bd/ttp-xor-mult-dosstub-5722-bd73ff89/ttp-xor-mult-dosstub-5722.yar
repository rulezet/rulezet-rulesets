rule TTP_XOR_MULT_DOSStub_5722 {
  strings:
    $key_5722 = { 03 4a [2] 77 52 [2] 30 50 [2] 77 41 [2] 39 4d [2] 35 47 [2] 22 4c [2] 39 02 [2] 04 }

  condition:
    any of them
}