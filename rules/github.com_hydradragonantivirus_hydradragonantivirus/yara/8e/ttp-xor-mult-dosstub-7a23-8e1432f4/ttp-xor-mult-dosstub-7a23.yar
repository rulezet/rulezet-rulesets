rule TTP_XOR_MULT_DOSStub_7a23 {
  strings:
    $key_7a23 = { 2e 4b [2] 5a 53 [2] 1d 51 [2] 5a 40 [2] 14 4c [2] 18 46 [2] 0f 4d [2] 14 03 [2] 29 }

  condition:
    any of them
}