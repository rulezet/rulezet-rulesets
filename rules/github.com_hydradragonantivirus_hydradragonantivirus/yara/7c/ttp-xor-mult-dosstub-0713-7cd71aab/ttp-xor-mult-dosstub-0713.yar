rule TTP_XOR_MULT_DOSStub_0713 {
  strings:
    $key_0713 = { 53 7b [2] 27 63 [2] 60 61 [2] 27 70 [2] 69 7c [2] 65 76 [2] 72 7d [2] 69 33 [2] 54 }

  condition:
    any of them
}