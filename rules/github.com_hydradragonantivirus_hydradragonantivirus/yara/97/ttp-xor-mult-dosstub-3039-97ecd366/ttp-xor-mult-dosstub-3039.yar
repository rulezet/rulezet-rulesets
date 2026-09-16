rule TTP_XOR_MULT_DOSStub_3039 {
  strings:
    $key_3039 = { 64 51 [2] 10 49 [2] 57 4b [2] 10 5a [2] 5e 56 [2] 52 5c [2] 45 57 [2] 5e 19 [2] 63 }

  condition:
    any of them
}