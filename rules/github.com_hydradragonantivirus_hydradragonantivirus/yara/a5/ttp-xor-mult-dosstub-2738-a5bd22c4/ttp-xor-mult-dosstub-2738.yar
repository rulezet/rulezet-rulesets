rule TTP_XOR_MULT_DOSStub_2738 {
  strings:
    $key_2738 = { 73 50 [2] 07 48 [2] 40 4a [2] 07 5b [2] 49 57 [2] 45 5d [2] 52 56 [2] 49 18 [2] 74 }

  condition:
    any of them
}