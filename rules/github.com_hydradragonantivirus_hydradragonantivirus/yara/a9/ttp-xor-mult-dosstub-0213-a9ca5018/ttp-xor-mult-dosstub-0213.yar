rule TTP_XOR_MULT_DOSStub_0213 {
  strings:
    $key_0213 = { 56 7b [2] 22 63 [2] 65 61 [2] 22 70 [2] 6c 7c [2] 60 76 [2] 77 7d [2] 6c 33 [2] 51 }

  condition:
    any of them
}