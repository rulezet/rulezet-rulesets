rule TTP_XOR_MULT_DOSStub_5039 {
  strings:
    $key_5039 = { 04 51 [2] 70 49 [2] 37 4b [2] 70 5a [2] 3e 56 [2] 32 5c [2] 25 57 [2] 3e 19 [2] 03 }

  condition:
    any of them
}