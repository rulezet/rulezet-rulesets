rule TTP_XOR_MULT_DOSStub_6325 {
  strings:
    $key_6325 = { 37 4d [2] 43 55 [2] 04 57 [2] 43 46 [2] 0d 4a [2] 01 40 [2] 16 4b [2] 0d 05 [2] 30 }

  condition:
    any of them
}