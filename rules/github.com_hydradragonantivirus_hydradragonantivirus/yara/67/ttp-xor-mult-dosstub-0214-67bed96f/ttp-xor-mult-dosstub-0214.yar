rule TTP_XOR_MULT_DOSStub_0214 {
  strings:
    $key_0214 = { 56 7c [2] 22 64 [2] 65 66 [2] 22 77 [2] 6c 7b [2] 60 71 [2] 77 7a [2] 6c 34 [2] 51 }

  condition:
    any of them
}