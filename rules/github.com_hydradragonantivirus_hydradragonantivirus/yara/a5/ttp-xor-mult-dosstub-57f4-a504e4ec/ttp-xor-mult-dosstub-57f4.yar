rule TTP_XOR_MULT_DOSStub_57f4 {
  strings:
    $key_57f4 = { 03 9c [2] 77 84 [2] 30 86 [2] 77 97 [2] 39 9b [2] 35 91 [2] 22 9a [2] 39 d4 [2] 04 }

  condition:
    any of them
}