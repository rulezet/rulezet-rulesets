rule TTP_XOR_MULT_DOSStub_3423 {
  strings:
    $key_3423 = { 60 4b [2] 14 53 [2] 53 51 [2] 14 40 [2] 5a 4c [2] 56 46 [2] 41 4d [2] 5a 03 [2] 67 }

  condition:
    any of them
}