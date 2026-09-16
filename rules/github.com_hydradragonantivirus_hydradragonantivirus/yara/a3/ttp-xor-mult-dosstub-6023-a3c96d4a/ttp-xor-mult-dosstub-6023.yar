rule TTP_XOR_MULT_DOSStub_6023 {
  strings:
    $key_6023 = { 34 4b [2] 40 53 [2] 07 51 [2] 40 40 [2] 0e 4c [2] 02 46 [2] 15 4d [2] 0e 03 [2] 33 }

  condition:
    any of them
}