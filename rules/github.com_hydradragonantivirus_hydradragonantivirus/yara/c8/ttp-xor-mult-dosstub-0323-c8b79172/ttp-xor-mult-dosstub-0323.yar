rule TTP_XOR_MULT_DOSStub_0323 {
  strings:
    $key_0323 = { 57 4b [2] 23 53 [2] 64 51 [2] 23 40 [2] 6d 4c [2] 61 46 [2] 76 4d [2] 6d 03 [2] 50 }

  condition:
    any of them
}