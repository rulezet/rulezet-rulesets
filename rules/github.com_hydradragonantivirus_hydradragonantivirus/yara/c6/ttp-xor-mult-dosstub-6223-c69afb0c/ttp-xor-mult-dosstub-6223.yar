rule TTP_XOR_MULT_DOSStub_6223 {
  strings:
    $key_6223 = { 36 4b [2] 42 53 [2] 05 51 [2] 42 40 [2] 0c 4c [2] 00 46 [2] 17 4d [2] 0c 03 [2] 31 }

  condition:
    any of them
}