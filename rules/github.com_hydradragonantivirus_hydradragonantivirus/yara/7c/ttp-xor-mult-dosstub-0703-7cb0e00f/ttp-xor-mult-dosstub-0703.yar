rule TTP_XOR_MULT_DOSStub_0703 {
  strings:
    $key_0703 = { 53 6b [2] 27 73 [2] 60 71 [2] 27 60 [2] 69 6c [2] 65 66 [2] 72 6d [2] 69 23 [2] 54 }

  condition:
    any of them
}