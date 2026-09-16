rule TTP_XOR_MULT_DOSStub_0219 {
  strings:
    $key_0219 = { 56 71 [2] 22 69 [2] 65 6b [2] 22 7a [2] 6c 76 [2] 60 7c [2] 77 77 [2] 6c 39 [2] 51 }

  condition:
    any of them
}