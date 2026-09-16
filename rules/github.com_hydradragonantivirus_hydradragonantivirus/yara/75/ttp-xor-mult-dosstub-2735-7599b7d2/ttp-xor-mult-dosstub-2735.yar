rule TTP_XOR_MULT_DOSStub_2735 {
  strings:
    $key_2735 = { 73 5d [2] 07 45 [2] 40 47 [2] 07 56 [2] 49 5a [2] 45 50 [2] 52 5b [2] 49 15 [2] 74 }

  condition:
    any of them
}