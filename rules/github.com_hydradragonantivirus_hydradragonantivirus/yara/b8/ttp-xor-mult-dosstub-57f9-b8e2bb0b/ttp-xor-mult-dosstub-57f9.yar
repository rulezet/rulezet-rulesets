rule TTP_XOR_MULT_DOSStub_57f9 {
  strings:
    $key_57f9 = { 03 91 [2] 77 89 [2] 30 8b [2] 77 9a [2] 39 96 [2] 35 9c [2] 22 97 [2] 39 d9 [2] 04 }

  condition:
    any of them
}