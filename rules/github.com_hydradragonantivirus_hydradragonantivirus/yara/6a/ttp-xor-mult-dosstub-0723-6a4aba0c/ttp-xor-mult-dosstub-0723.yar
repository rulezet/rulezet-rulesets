rule TTP_XOR_MULT_DOSStub_0723 {
  strings:
    $key_0723 = { 53 4b [2] 27 53 [2] 60 51 [2] 27 40 [2] 69 4c [2] 65 46 [2] 72 4d [2] 69 03 [2] 54 }

  condition:
    any of them
}