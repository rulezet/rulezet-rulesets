rule TTP_XOR_MULT_DOSStub_7139 {
  strings:
    $key_7139 = { 25 51 [2] 51 49 [2] 16 4b [2] 51 5a [2] 1f 56 [2] 13 5c [2] 04 57 [2] 1f 19 [2] 22 }

  condition:
    any of them
}