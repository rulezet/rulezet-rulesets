rule TTP_XOR_MULT_DOSStub_2a13 {
  strings:
    $key_2a13 = { 7e 7b [2] 0a 63 [2] 4d 61 [2] 0a 70 [2] 44 7c [2] 48 76 [2] 5f 7d [2] 44 33 [2] 79 }

  condition:
    any of them
}