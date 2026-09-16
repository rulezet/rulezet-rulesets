rule TTP_XOR_MULT_DOSStub_1639 {
  strings:
    $key_1639 = { 42 51 [2] 36 49 [2] 71 4b [2] 36 5a [2] 78 56 [2] 74 5c [2] 63 57 [2] 78 19 [2] 45 }

  condition:
    any of them
}