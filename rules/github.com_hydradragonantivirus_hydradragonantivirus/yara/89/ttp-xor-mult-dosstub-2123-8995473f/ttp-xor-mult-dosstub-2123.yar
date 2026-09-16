rule TTP_XOR_MULT_DOSStub_2123 {
  strings:
    $key_2123 = { 75 4b [2] 01 53 [2] 46 51 [2] 01 40 [2] 4f 4c [2] 43 46 [2] 54 4d [2] 4f 03 [2] 72 }

  condition:
    any of them
}