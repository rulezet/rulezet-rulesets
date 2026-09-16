rule TTP_XOR_MULT_DOSStub_35f9 {
  strings:
    $key_35f9 = { 61 91 [2] 15 89 [2] 52 8b [2] 15 9a [2] 5b 96 [2] 57 9c [2] 40 97 [2] 5b d9 [2] 66 }

  condition:
    any of them
}